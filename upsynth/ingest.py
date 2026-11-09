"""ingest: pcap -> flows.parquet

Cuts packets into bidirectional 5-tuple flows (TCP ends on FIN/RST, UDP after an idle timeout),
keeps per-flow counters, the first SEQ_LEN signed lengths and gaps, and the cleartext names a DPI
would use: DNS (same UE, time window), TLS / QUIC SNI, ALPN, JA4, HTTP Host. IPs and TEIDs become
HMAC tokens before anything is written; no payload is kept.
"""

from __future__ import annotations

import ipaddress
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import dpkt
import pyarrow as pa
import pyarrow.parquet as pq

from . import quic, tls
from .anon import Anonymizer
from .asn import AsnDB
from .pcapio import Packet, ReadStats, iter_packets
from .schemas import FLOW_SCHEMA, RATE_BINS, SEQ_LEN

# ports where the side using them is the server
SERVER_PORTS = {
    20, 21, 22, 25, 53, 67, 80, 110, 123, 143, 443, 465, 500, 587, 853, 993, 995, 1194, 1701, 1723, 1935,
    3389, 3478, 3479, 3480, 3481, 4500, 5060, 5061, 5222, 5223, 5228, 5349, 8000, 8080, 8443, 8801, 8802,
    8883, 9000, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309, 51820,
}
TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10
MAX_HELLO_SEGMENTS = 12
MAX_QUIC_INITIALS = 6
BATCH = 50_000


def _private(ip: bytes) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_link_local or a.is_loopback or (a.version == 4 and a in _CGNAT)


_CGNAT = ipaddress.ip_network("100.64.0.0/10")


@dataclass(slots=True)
class Flow:
    proto: int
    ver: int
    ue_ip: bytes
    ue_port: int
    srv_ip: bytes
    srv_port: int
    start: float
    iface: str
    last: float = 0.0
    pkts_up: int = 0
    pkts_down: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    seq_len: list = field(default_factory=list)
    seq_iat: list = field(default_factory=list)
    rate_up: list = field(default_factory=list)
    rate_down: list = field(default_factory=list)
    syn_t: float | None = None
    hs_ms: float | None = None
    teid_ul: int | None = None
    teid_dl: int | None = None
    qfi: int | None = None
    fin_up: bool = False
    fin_down: bool = False
    end_reason: str | None = None
    # handshake parsing state
    hello_done: bool = False
    client_isn: int | None = None
    client_segs: dict | None = None
    quic_dcid: bytes | None = None
    quic_crypto: dict | None = None
    quic_tries: int = 0
    dns_name: str | None = None
    sni: str | None = None
    alpn: str | None = None
    ja4: str | None = None
    ja4_r: str | None = None
    quic_version: str | None = None
    http_host: str | None = None


class DnsCache:
    """Answers seen per UE: (ue_ip, answer_ip) -> (query name, time). Lookups honour a time window."""

    def __init__(self, window: float):
        self.window = window
        self._m: dict[tuple[bytes, bytes], tuple[str, float]] = {}

    def add(self, ue_ip: bytes, answer_ip: bytes, name: str, ts: float) -> None:
        self._m[(ue_ip, answer_ip)] = (name, ts)

    def get(self, ue_ip: bytes, srv_ip: bytes, ts: float) -> str | None:
        hit = self._m.get((ue_ip, srv_ip))
        if hit and -2.0 <= ts - hit[1] <= self.window:
            return hit[0]
        return None


def _decide_ue_side(p: Packet) -> bool:
    """True if the packet's source is the UE (client) side."""
    if p.pdu_type is not None:
        return p.pdu_type == 1
    if p.proto == 6:
        if p.tcp_flags & TCP_SYN:
            return not (p.tcp_flags & TCP_ACK)
    s_srv, d_srv = p.sport in SERVER_PORTS, p.dport in SERVER_PORTS
    if d_srv and not s_srv:
        return True
    if s_srv and not d_srv:
        return False
    if p.dport < 1024 <= p.sport:
        return True
    if p.sport < 1024 <= p.dport:
        return False
    sp, dp = _private(p.src), _private(p.dst)
    if sp and not dp:
        return True
    if dp and not sp:
        return False
    return True


class Ingest:
    def __init__(self, anon: Anonymizer, asn_db: AsnDB | None = None, *, udp_idle: float = 120.0,
                 tcp_idle: float = 600.0, dns_window: float = 600.0, ndpi: dict | None = None,
                 ue: str | None = None):
        self.anon = anon
        self.asn_db = asn_db
        self.ue = ue  # one handset: its IPv4 and IPv6 addresses (and address changes) are one UE
        self.udp_idle = udp_idle
        self.tcp_idle = tcp_idle
        self.dns = DnsCache(dns_window)
        self.ndpi = ndpi or {}
        self.active: dict[tuple, Flow] = {}
        self.done: list[Flow] = []
        self.flow_id = 0
        self.last_sweep = 0.0
        self.asn_cache: dict[bytes, int | None] = {}
        self.counts = defaultdict(int)

    # ------------------------------------------------------------ packets

    def feed(self, p: Packet) -> None:
        a, b = (p.src, p.sport), (p.dst, p.dport)
        key = (p.proto, a, b) if a <= b else (p.proto, b, a)
        f = self.active.get(key)
        if f is not None:
            idle = self.tcp_idle if p.proto == 6 else self.udp_idle
            syn_only = p.proto == 6 and p.tcp_flags & TCP_SYN and not p.tcp_flags & TCP_ACK
            ended = f.end_reason or (f.fin_up and f.fin_down)
            if p.ts - f.last > idle:
                self._close(key, "idle")
                f = None
            elif (syn_only and f.pkts_up + f.pkts_down > 3) or (ended and p.ts - f.last > 2.0):
                self._close(key, f.end_reason or ("fin" if f.fin_up or f.fin_down else "idle"))
                f = None
        if f is None:
            up = _decide_ue_side(p)
            ue, srv = (a, b) if up else (b, a)
            f = Flow(p.proto, p.ver, ue[0], ue[1], srv[0], srv[1], p.ts, "n3" if p.teid is not None else "n6")
            f.last = p.ts
            f.dns_name = self.dns.get(self.ue or f.ue_ip, f.srv_ip, p.ts)
            self.active[key] = f
        up = p.src == f.ue_ip and p.sport == f.ue_port
        self._count(f, p, up)
        if p.proto == 6:
            self._tcp(f, p, up)
        elif p.proto == 17:
            if f.srv_port == 53 or p.sport == 53:
                self._dns(f, p, up)
            elif not f.hello_done and up and p.payload:
                self._quic(f, p)
        if p.ts - self.last_sweep > 10.0:
            self._sweep(p.ts)

    def _count(self, f: Flow, p: Packet, up: bool) -> None:
        n = f.pkts_up + f.pkts_down
        if n < SEQ_LEN:
            f.seq_len.append(min(p.ip_len, 32767) if up else -min(p.ip_len, 32767))
            f.seq_iat.append(0.0 if n == 0 else (p.ts - f.last) * 1000.0)
        sec = int(p.ts - f.start)
        if 0 <= sec < RATE_BINS:
            series = f.rate_up if up else f.rate_down
            if len(series) <= sec:
                series.extend([0] * (sec + 1 - len(series)))
            series[sec] += p.ip_len
        if f.proto == 17 and f.hs_ms is None and not up and f.pkts_down == 0 and f.pkts_up > 0:
            f.hs_ms = (p.ts - f.start) * 1000.0
        if up:
            f.pkts_up += 1
            f.bytes_up += p.ip_len
            if p.teid is not None:
                f.teid_ul = p.teid
        else:
            f.pkts_down += 1
            f.bytes_down += p.ip_len
            if p.teid is not None:
                f.teid_dl = p.teid
        if p.qfi is not None:
            f.qfi = p.qfi
        f.last = max(f.last, p.ts)

    def _tcp(self, f: Flow, p: Packet, up: bool) -> None:
        fl = p.tcp_flags
        if fl & TCP_RST:
            f.end_reason = "rst"
        if fl & TCP_FIN:
            if up:
                f.fin_up = True
            else:
                f.fin_down = True
        if up and f.hs_ms is None and f.syn_t is not None and fl & TCP_ACK and not fl & TCP_SYN:
            f.hs_ms = (p.ts - f.syn_t) * 1000.0
        if not up or f.hello_done:
            return
        if fl & TCP_SYN:
            f.client_isn = p.tcp_seq
            f.syn_t = p.ts
            return
        if not p.payload:
            return
        if f.client_segs is None:
            f.client_segs = {}
        if len(f.client_segs) >= MAX_HELLO_SEGMENTS:
            f.hello_done = True
            f.client_segs = None
            return
        f.client_segs.setdefault(p.tcp_seq, p.payload)
        base = (f.client_isn + 1) & 0xFFFFFFFF if f.client_isn is not None else min(f.client_segs)
        stream = bytearray()
        seq = base
        while seq in f.client_segs:
            seg = f.client_segs[seq]
            stream += seg
            seq = (seq + len(seg)) & 0xFFFFFFFF
        if not stream:
            return
        if stream[0] == 22:
            msg = tls.handshake_from_records(bytes(stream))
            if msg is None:
                if len(stream) > 5 and stream[5] != 1:
                    f.hello_done = True
                return
            ch = tls.parse_client_hello(msg)
            if ch:
                f.sni = ch.sni
                f.alpn = ",".join(ch.alpn) or None
                f.ja4, f.ja4_r = tls.ja4(ch, "t")
        elif stream[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"CONN", b"DELE", b"PATC"):
            head = bytes(stream[:4096]).split(b"\r\n\r\n", 1)[0]
            for line in head.split(b"\r\n")[1:]:
                if line[:5].lower() == b"host:":
                    f.http_host = line[5:].strip().decode("ascii", "replace").split(":")[0].lower()
                    break
            else:
                if b"\r\n\r\n" not in stream:
                    return
        f.hello_done = True
        f.client_segs = None

    def _quic(self, f: Flow, p: Packet) -> None:
        d = p.payload
        f.quic_tries += 1
        if f.quic_tries > MAX_QUIC_INITIALS:
            f.hello_done = True
            f.quic_crypto = None
            return
        if not quic.is_long_header(d):
            if f.quic_dcid is None:
                f.hello_done = True
            return
        off = 0
        while off < len(d) and quic.is_long_header(d[off:]):
            dcid_here = d[off + 6 : off + 6 + d[off + 5]] if off + 5 < len(d) else b""
            if f.quic_dcid is None:
                f.quic_dcid = dcid_here
            hdr = quic.parse_long(d, off, keys_dcid=f.quic_dcid)
            if hdr is not None and hdr.ptype == "initial" and hdr.payload is None and dcid_here != f.quic_dcid:
                hdr = quic.parse_long(d, off, keys_dcid=dcid_here)  # after a Retry the keys follow the new DCID
            if hdr is None:
                break
            if hdr.version in (quic.V1, quic.V2) or f.quic_version is None:
                f.quic_version = f"0x{hdr.version:08x}"
            if hdr.ptype == "initial" and hdr.payload:
                if f.quic_crypto is None:
                    f.quic_crypto = {}
                for o, data in quic.crypto_frames(hdr.payload):
                    f.quic_crypto.setdefault(o, data)
            if hdr.size <= 0:
                break
            off += hdr.size
        if f.quic_crypto:
            buf = b""
            while len(buf) in f.quic_crypto:
                buf += f.quic_crypto[len(buf)]
            if len(buf) >= 4 and buf[0] == 1:
                n = int.from_bytes(buf[1:4], "big")
                if len(buf) >= 4 + n:
                    ch = tls.parse_client_hello(buf[: 4 + n])
                    if ch:
                        f.sni = ch.sni
                        f.alpn = ",".join(ch.alpn) or None
                        f.ja4, f.ja4_r = tls.ja4(ch, "q")
                    f.hello_done = True
                    f.quic_crypto = None

    def _dns(self, f: Flow, p: Packet, up: bool) -> None:
        if not p.payload:
            return
        try:
            m = dpkt.dns.DNS(p.payload)
        except (dpkt.UnpackError, struct.error, IndexError):
            return
        qname = m.qd[0].name.lower().rstrip(".") if m.qd else None
        if not up and m.qr == dpkt.dns.DNS_R and qname:
            for rr in m.an:
                if rr.type == dpkt.dns.DNS_A and len(rr.rdata) == 4:
                    self.dns.add(self.ue or f.ue_ip, rr.rdata, qname, p.ts)
                elif rr.type == dpkt.dns.DNS_AAAA and len(rr.rdata) == 16:
                    self.dns.add(self.ue or f.ue_ip, rr.rdata, qname, p.ts)

    # ------------------------------------------------------------ flow end

    def _sweep(self, now: float) -> None:
        self.last_sweep = now
        for key, f in list(self.active.items()):
            idle = self.tcp_idle if f.proto == 6 else self.udp_idle
            if now - f.last > idle:
                self._close(key, "idle")
            elif f.end_reason == "rst" or (f.fin_up and f.fin_down and now - f.last > 2.0):
                self._close(key, f.end_reason or "fin")

    def _close(self, key, reason: str) -> None:
        f = self.active.pop(key)
        if f.end_reason is None:
            f.end_reason = "fin" if (f.fin_up and f.fin_down) and reason != "idle" else reason
        self.done.append(f)

    def finish(self) -> None:
        for key, f in list(self.active.items()):
            if f.end_reason:
                self._close(key, f.end_reason)
            elif f.fin_up and f.fin_down:
                self._close(key, "fin")
            else:
                self._close(key, "eof")

    def _asn(self, ip: bytes) -> int | None:
        if self.asn_db is None:
            return None
        if ip not in self.asn_cache:
            self.asn_cache[ip] = self.asn_db.lookup(ip)
        return self.asn_cache[ip]

    def rows(self, flows: list[Flow]) -> dict[str, list]:
        cols: dict[str, list] = {f.name: [] for f in FLOW_SCHEMA}
        a = self.anon
        for f in flows:
            self.flow_id += 1
            self.counts["flows"] += 1
            self.counts[f.iface] += 1
            if f.sni:
                self.counts["sni"] += 1
            if f.dns_name:
                self.counts["dns_name"] += 1
            if f.quic_version:
                self.counts["quic"] += 1
            ndpi = None
            if self.ndpi:
                ndpi = _match_ndpi(self.ndpi, f)
            cols["flow_id"].append(self.flow_id)
            cols["iface"].append(f.iface)
            cols["ue"].append(self.ue or a.ip(f.ue_ip))
            cols["server"].append(a.ip(f.srv_ip))
            cols["ip_version"].append(f.ver)
            cols["proto"].append(f.proto)
            cols["ue_port"].append(f.ue_port)
            cols["server_port"].append(f.srv_port)
            cols["teid_ul"].append(a.teid(f.teid_ul) if f.teid_ul is not None else None)
            cols["teid_dl"].append(a.teid(f.teid_dl) if f.teid_dl is not None else None)
            cols["qfi"].append(f.qfi)
            cols["start"].append(f.start)
            cols["end"].append(f.last)
            cols["duration"].append(f.last - f.start)
            cols["pkts_up"].append(f.pkts_up)
            cols["pkts_down"].append(f.pkts_down)
            cols["bytes_up"].append(f.bytes_up)
            cols["bytes_down"].append(f.bytes_down)
            cols["seq_len"].append(f.seq_len)
            cols["seq_iat"].append([round(x, 3) for x in f.seq_iat])
            cols["rate_up"].append(f.rate_up)
            cols["rate_down"].append(f.rate_down)
            cols["hs_ms"].append(round(f.hs_ms, 3) if f.hs_ms is not None else None)
            cols["end_reason"].append(f.end_reason)
            cols["dns_name"].append(f.dns_name)
            cols["sni"].append(f.sni)
            cols["alpn"].append(f.alpn)
            cols["ja4"].append(f.ja4)
            cols["ja4_r"].append(f.ja4_r)
            cols["quic_version"].append(f.quic_version)
            cols["http_host"].append(f.http_host)
            cols["asn"].append(self._asn(f.srv_ip))
            cols["ndpi_app"].append(ndpi)
        return cols


def _canon(proto: int, a_ip: bytes, a_port: int, b_ip: bytes, b_port: int) -> tuple:
    a, b = (a_ip, a_port), (b_ip, b_port)
    return (proto, a, b) if a <= b else (proto, b, a)


def _match_ndpi(index: dict, f: Flow) -> str | None:
    cands = index.get(_canon(f.proto, f.ue_ip, f.ue_port, f.srv_ip, f.srv_port))
    if not cands:
        return None
    best = min(cands, key=lambda c: abs(c[0] - f.start))
    return best[1] if abs(best[0] - f.start) < 5.0 else None


def ndpi_index(path: str | Path) -> dict:
    """Run nfstream (nDPI) over the capture for weak labels. Needs the optional 'ndpi' extra."""
    try:
        from nfstream import NFStreamer
    except ImportError as e:  # pragma: no cover - optional
        raise RuntimeError("nfstream is not installed; pip install 'upsynth[ndpi]'") from e
    idx: dict = defaultdict(list)
    for fl in NFStreamer(source=str(path), decode_tunnels=True, statistical_analysis=False, idle_timeout=120):
        try:
            k = _canon(fl.protocol, ipaddress.ip_address(fl.src_ip).packed, fl.src_port,
                       ipaddress.ip_address(fl.dst_ip).packed, fl.dst_port)
        except ValueError:
            continue
        name = fl.application_name or None
        if name and name != "Unknown":
            idx[k].append((fl.bidirectional_first_seen_ms / 1000.0, name))
    return dict(idx)


def run(pcap: str | Path, out: str | Path, *, key: bytes, asn_db: str | Path | None = None,
        udp_idle: float = 120.0, tcp_idle: float = 600.0, dns_window: float = 600.0, use_ndpi: bool = False,
        ue: str | None = None) -> dict:
    db = AsnDB.load(asn_db) if asn_db else None
    ndpi = ndpi_index(pcap) if use_ndpi else None
    ing = Ingest(Anonymizer(key), db, udp_idle=udp_idle, tcp_idle=tcp_idle, dns_window=dns_window, ndpi=ndpi, ue=ue)
    stats = ReadStats()
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    writer = pq.ParquetWriter(out, FLOW_SCHEMA)
    packets = 0
    try:
        for p in iter_packets(pcap, stats):
            packets += 1
            ing.feed(p)
            if len(ing.done) >= BATCH:
                writer.write_table(pa.table(ing.rows(ing.done), schema=FLOW_SCHEMA))
                ing.done = []
        ing.finish()
        ing.done.sort(key=lambda f: f.start)
        if ing.done or ing.counts["flows"] == 0:
            writer.write_table(pa.table(ing.rows(ing.done), schema=FLOW_SCHEMA))
    finally:
        writer.close()
    c = ing.counts
    return {
        "input": str(pcap),
        "output": str(out),
        "frames": stats.frames,
        "user_packets": packets,
        "gtpu_packets": stats.gtpu,
        "skipped": {"non_ip": stats.non_ip, "other_l4": stats.other_l4, "fragments": stats.fragments,
                    "gtpu_signalling": stats.gtpu_other, "truncated": stats.truncated},
        "flows": c["flows"],
        "flows_n3": c["n3"],
        "flows_n6": c["n6"],
        "with_sni": c["sni"],
        "with_dns_name": c["dns_name"],
        "quic": c["quic"],
        "asn_db": str(asn_db) if asn_db else None,
    }
