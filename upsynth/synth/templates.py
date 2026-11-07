"""Packet layer: turn a FlowSpec into valid IP packets.

A template gets the flow spec and a context (addresses, random source, MTU) and returns
(timestamp, uplink, ip_packet) tuples. Templates are registered by name; an app picks one through
kb/apps.yaml "template" or by transport. Every byte stream is self-consistent (TCP sequence numbers,
TLS record lengths, QUIC Initial protection) so Wireshark parses it without malformed packets.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import numpy as np

from .. import quic, tls
from . import packets as P
from . import protocols
from .behavior import FlowSpec

Pkt = tuple[float, bool, bytes]
TEMPLATES: dict[str, Callable[["FlowSpec", "Ctx"], list[Pkt]]] = {}


def template(name: str):
    def deco(fn):
        TEMPLATES[name] = fn
        return fn

    return deco


@dataclass
class Ctx:
    rng: np.random.Generator
    ue_ip: bytes
    srv_ip: bytes
    ue_port: int
    mtu: int

    def rnd(self, n: int) -> bytes:
        return self.rng.bytes(n) if n > 0 else b""

    def ms(self, lo: float, hi: float) -> float:
        return float(self.rng.uniform(lo, hi)) / 1000.0


def _times(spec: FlowSpec) -> list[tuple[float, bool, int]]:
    out, t = [], spec.start
    for v, gap in spec.shape:
        t += gap / 1000.0
        out.append((t, v > 0, abs(v)))
    return out


# ---------------------------------------------------------------- TCP machinery


class TcpConn:
    def __init__(self, ctx: Ctx, port: int, t0: float):
        r = ctx.rng
        self.ctx = ctx
        self.port = port
        self.t0 = t0
        self.seq = {True: int(r.integers(0, 2**32)), False: int(r.integers(0, 2**32))}
        self.ts_base = {True: int(r.integers(1, 2**31)), False: int(r.integers(1, 2**31))}
        self.last_ts = {True: 0, False: 0}
        self.ident = {True: int(r.integers(0, 65536)), False: int(r.integers(0, 65536))}
        self.synced = False
        self.out: list[Pkt] = []
        v4 = len(ctx.ue_ip) == 4
        self.mss = ctx.mtu - (20 if v4 else 40) - P.TCP_TS_HDR

    def send(self, t: float, up: bool, flags: int, payload: bytes = b"") -> None:
        c = self.ctx
        src, dst = (c.ue_ip, c.srv_ip) if up else (c.srv_ip, c.ue_ip)
        sp, dp = (c.ue_port, self.port) if up else (self.port, c.ue_port)
        tsval = (self.ts_base[up] + int((t - self.t0) * 1000)) & 0xFFFFFFFF
        ack = self.seq[not up] if flags & P.TCP_ACK else 0
        seg = P.tcp(src, dst, sp, dp, self.seq[up], ack, flags, payload, tsval=tsval, tsecr=self.last_ts[not up],
                    syn_mss=self.mss + P.TCP_TS_HDR - 20)
        self.last_ts[up] = tsval
        self.ident[up] += 1
        self.out.append((t, up, P.ip_packet(src, dst, 6, seg, ident=self.ident[up], ttl=64 if up else 54)))
        self.seq[up] = (self.seq[up] + len(payload) + (1 if flags & (P.TCP_SYN | P.TCP_FIN) else 0)) & 0xFFFFFFFF


@dataclass
class Item:
    t: float
    up: bool
    cap: int  # TCP payload bytes, 0 = pure ACK


def _tcp_items(spec: FlowSpec, ctx: Ctx, conn: TcpConn) -> tuple[list[float], list[Item]]:
    """Split the shape into three handshake times and data / ACK items."""
    hdr = (20 if len(ctx.ue_ip) == 4 else 40) + P.TCP_TS_HDR
    ts = _times(spec)
    hs = [x[0] for x in ts[:3]]
    while len(hs) < 3:
        hs.append((hs[-1] if hs else spec.start) + ctx.ms(5, 40))
    items = [Item(t, up, min(max(size - hdr, 0), conn.mss)) for t, up, size in ts[3:]]
    for it in items:
        if 0 < it.cap < 8:  # tiny segments in real traces are keep-alives; treat as ACKs
            it.cap = 0
    return hs, items


def _bursts(items: list[Item]) -> list[list[Item]]:
    out: list[list[Item]] = []
    for it in items:
        if it.cap == 0:
            continue
        if out and out[-1][0].up == it.up:
            out[-1].append(it)
        else:
            out.append([it])
    return out


def _grow(burst: list[Item], items: list[Item], need: int, mss: int) -> None:
    """Make the burst carry at least `need` bytes: fill segments to MSS, then add segments after it."""
    have = sum(i.cap for i in burst)
    for it in burst:
        if have >= need:
            return
        add = min(mss - it.cap, need - have)
        it.cap += add
        have += add
    while have < need:
        last = burst[-1]
        new = Item(last.t + 0.00001, last.up, min(mss, need - have))
        items.insert(items.index(last) + 1, new)
        burst.append(new)
        have += new.cap


def _exact(burst: list[Item], items: list[Item], size: int, mss: int) -> None:
    """Make the burst carry exactly `size` bytes."""
    left = size
    for it in burst:
        it.cap = min(mss, left)
        left -= it.cap
    if left > 0:
        _grow(burst, items, size, mss)
    for it in list(burst):
        if it.cap == 0:
            burst.remove(it)


def _app_records(n: int, ctx: Ctx, ctype: int = 23) -> bytes:
    """Exactly n bytes of TLS records (n == 0 or n >= 22)."""
    out = []
    while n > 0:
        take = min(n, 16406)
        if 0 < n - take < 22:
            take = n - 22
        out.append(tls.record(ctype, ctx.rnd(take - 5)))
        n -= take
    return b"".join(out)


def _fill_and_send(conn: TcpConn, hs: list[float], items: list[Item], contents: list[bytes], bursts: list[list[Item]],
                   ctx: Ctx) -> list[Pkt]:
    conn.send(hs[0], True, P.TCP_SYN)
    conn.send(hs[1], False, P.TCP_SYN | P.TCP_ACK)
    conn.send(hs[2], True, P.TCP_ACK)
    payload_of: dict[int, bytes] = {}
    psh: set[int] = set()
    for burst, data in zip(bursts, contents):
        p = 0
        for it in burst:
            payload_of[id(it)] = data[p : p + it.cap]
            p += it.cap
        psh.add(id(burst[-1]))
    last_t = hs[2]
    for it in items:
        t = max(it.t, last_t)
        last_t = t
        data = payload_of.get(id(it), b"")
        if data:
            conn.send(t, it.up, P.TCP_ACK | (P.TCP_PSH if id(it) in psh else 0), data)
        else:
            conn.send(t, it.up, P.TCP_ACK)
    t = last_t + ctx.ms(1, 80)
    conn.send(t, True, P.TCP_FIN | P.TCP_ACK)
    t += ctx.ms(5, 40)
    conn.send(t, False, P.TCP_FIN | P.TCP_ACK)
    conn.send(t + ctx.ms(0.05, 0.5), True, P.TCP_ACK)
    return conn.out


def _first_data_up(items: list[Item]) -> None:
    first = next((i for i in items if i.cap), None)
    if first is None:
        items.append(Item((items[-1].t if items else 0) + 0.0001, True, 1))
    elif not first.up:
        items.insert(items.index(first), Item(first.t - 0.00001, True, 1))


def _ensure_down_after(items: list[Item]) -> None:
    """Make sure a server data burst follows the first client burst (the ServerHello goes there)."""
    bursts = _bursts(items)
    if len(bursts) < 2:
        last = bursts[0][-1]
        items.insert(items.index(last) + 1, Item(last.t + 0.03, False, 1))


@template("tls_tcp")
def tls_tcp(spec: FlowSpec, ctx: Ctx) -> list[Pkt]:
    conn = TcpConn(ctx, spec.server_port, spec.start)
    hs, items = _tcp_items(spec, ctx, conn)
    _first_data_up(items)
    _ensure_down_after(items)
    ja4_r = spec.ja4_r or tls.CHROME_JA4_R
    tls13 = ja4_r[1:3] == "13"
    ch = tls.build_client_hello(ja4_r, spec.domain, spec.alpn, rnd=ctx.rnd)
    ch_rec = tls.record(22, ch, 0x0301)
    sid = tls.session_id_of(ch)
    if tls13:
        sh = tls.record(22, tls.build_server_hello(tls13=True, session_id=sid, rnd=ctx.rnd))
        down0 = sh + tls.record(20, b"\x01")
        up1 = tls.record(20, b"\x01")
    else:
        cipher = next((int(c, 16) for c in ja4_r.split("_")[1].split(",") if c.startswith("c0")), 0xC02F)
        sh = tls.record(22, tls.build_server_hello(tls13=False, session_id=sid, cipher=cipher, rnd=ctx.rnd))
        down0 = sh + tls.record(20, b"\x01") + tls.record(22, ctx.rnd(40))
        up1 = tls.record(20, b"\x01") + tls.record(22, ctx.rnd(40))
    bursts = _bursts(items)
    _exact(bursts[0], items, len(ch_rec), conn.mss)
    bursts = _bursts(items)
    contents = [ch_rec]
    n_up, n_down = 1, 0
    for b in bursts[1:]:
        if b[0].up:
            prefix = up1 if n_up == 1 else b""
            n_up += 1
        else:
            prefix = down0 if n_down == 0 else b""
            n_down += 1
        rest = sum(i.cap for i in b) - len(prefix)
        if rest < 0:
            _grow(b, items, len(prefix), conn.mss)
            rest = 0
        elif 0 < rest < 22:
            _grow(b, items, len(prefix) + 22, conn.mss)
            rest = 22
        contents.append(prefix + _app_records(rest, ctx))
    return _fill_and_send(conn, hs, items, contents, bursts, ctx)


WEB_PAGE_SHAPE = [60, -60, 52, 600, -1400, -1400, -1400, -900, 52, 120, 450, -52, -1400, -1400, -1400, 52, -1400,
                  -1400, -1400, -1400, 52, -1400, -1400, -1400, -800, 52, 300, -1400, -1400, -600, 52, -52]


@template("web_browsing")
def web_browsing(spec: FlowSpec, ctx: Ctx) -> list[Pkt]:
    """Page load over HTTP/2 + TLS 1.3. Uses the profile shape; a built-in page load if there is none."""
    if len(spec.shape) < 6:
        gaps = [0.0, 20.0, 0.2, 0.5, 25.0] + [float(ctx.rng.uniform(0.05, 8.0)) for _ in WEB_PAGE_SHAPE[5:]]
        spec.shape = list(zip(WEB_PAGE_SHAPE, gaps))
    if not spec.alpn and (spec.ja4_r or tls.CHROME_JA4_R)[8:10] == "h2":
        spec.alpn = ["h2", "http/1.1"]
    return tls_tcp(spec, ctx)


@template("tcp")
def plain_tcp(spec: FlowSpec, ctx: Ctx) -> list[Pkt]:
    """Cleartext protocols by port (HTTP, MQTT, SIP, RTMP); opaque bytes on other ports."""
    conn = TcpConn(ctx, spec.server_port, spec.start)
    hs, items = _tcp_items(spec, ctx, conn)
    codec = protocols.TCP_CODECS.get(spec.server_port, protocols.opaque)
    if protocols.client_speaks_first(spec.server_port):
        _first_data_up(items)
    bursts = _bursts(items)
    r = protocols.Rnd(ctx.rng)
    state: dict = {}
    idx = {True: 0, False: 0}
    contents = []
    for b in bursts:
        up = b[0].up
        data = codec(state, r, up, idx[up], sum(i.cap for i in b), spec.domain or "example.net")
        idx[up] += 1
        _exact(b, items, len(data), conn.mss)
        contents.append(data)
    return _fill_and_send(conn, hs, items, contents, bursts, ctx)


# ---------------------------------------------------------------- UDP


def _udp_pkt(ctx: Ctx, port: int, up: bool, payload: bytes, ident: int) -> bytes:
    src, dst = (ctx.ue_ip, ctx.srv_ip) if up else (ctx.srv_ip, ctx.ue_ip)
    sp, dp = (ctx.ue_port, port) if up else (port, ctx.ue_port)
    return P.ip_packet(src, dst, 17, P.udp(src, dst, sp, dp, payload), ident=ident, ttl=64 if up else 54)


def _udp_overhead(ctx: Ctx) -> int:
    return (20 if len(ctx.ue_ip) == 4 else 40) + 8


@template("quic")
def quic_flow(spec: FlowSpec, ctx: Ctx) -> list[Pkt]:
    """QUIC v1: real Initial packets (ClientHello with SNI / ALPN / JA4, ServerHello), then opaque Handshake
    and 1-RTT packets sized by the shape."""
    ov = _udp_overhead(ctx)
    ts = _times(spec)
    if not ts or not ts[0][1]:
        ts.insert(0, (spec.start, True, 1250))
    dcid0, cscid, sscid = ctx.rnd(8), ctx.rnd(8), ctx.rnd(8)
    ck, sk = quic.initial_keys(dcid0)
    ja4_r = spec.ja4_r or tls.CHROME_QUIC_JA4_R
    ch = tls.build_client_hello(ja4_r, spec.domain, spec.alpn or ["h3"], quic_scid=cscid, rnd=ctx.rnd)
    chunks = [ch[i : i + 1100] for i in range(0, len(ch), 1100)]
    out: list[Pkt] = []
    ident = {True: int(ctx.rng.integers(65536)), False: int(ctx.rng.integers(65536))}

    def emit(t, up, payload):
        ident[up] += 1
        out.append((t, up, _udp_pkt(ctx, spec.server_port, up, payload, ident[up])))

    t0 = ts[0][0]
    pad = max(1200, min(ts[0][2] - ov, ctx.mtu - ov))
    for i, c in enumerate(chunks):
        emit(t0 + i * 0.00002, True, quic.build_initial(version=quic.V1, dcid=dcid0, scid=cscid, pn=i,
                                                        frames=quic.crypto_frame(i * 1100, c), keys=ck, pad_to=pad))
    first_down = True
    hs_down = 0
    hs_up = 0
    spn = 0
    for t, up, size in ts[1:]:
        body = max(size - ov, 30)
        if up:
            if hs_up == 0:
                emit(t, True, quic.build_long_opaque(version=quic.V1, ptype="handshake", dcid=sscid, scid=cscid,
                                                     body=ctx.rnd(max(body - 26, 24))))
                hs_up += 1
            else:
                emit(t, True, quic.build_short(sscid, ctx.rnd(max(body - 8, 20))))
        else:
            if first_down:
                sh = tls.build_server_hello(tls13=True, rnd=ctx.rnd)
                ini = quic.build_initial(version=quic.V1, dcid=cscid, scid=sscid, pn=spn,
                                         frames=quic.ack_frame(len(chunks) - 1) + quic.crypto_frame(0, sh), keys=sk)
                spn += 1
                room = body - len(ini) - 26
                if room >= 24:
                    ini += quic.build_long_opaque(version=quic.V1, ptype="handshake", dcid=cscid, scid=sscid,
                                                  body=ctx.rnd(room))
                emit(t, False, ini)
                first_down = False
            elif hs_down < 2 and body > 200:
                emit(t, False, quic.build_long_opaque(version=quic.V1, ptype="handshake", dcid=cscid, scid=sscid,
                                                      body=ctx.rnd(max(body - 26, 24))))
                hs_down += 1
            else:
                emit(t, False, quic.build_short(cscid, ctx.rnd(max(body - 8, 20))))
    return out


@template("udp")
def udp_flow(spec: FlowSpec, ctx: Ctx) -> list[Pkt]:
    """Datagrams in the format the port expects (NTP, STUN, WireGuard, OpenVPN, IKE, ESP, RakNet, SIP);
    RTP-shaped for conferencing and voice elsewhere; opaque otherwise."""
    ov = _udp_overhead(ctx)
    codec = protocols.UDP_CODECS.get(spec.server_port)
    if codec is None and spec.category in ("conferencing", "voip"):
        codec = protocols.rtp
    r = protocols.Rnd(ctx.rng)
    state: dict = {}
    out = []
    ident = {True: int(ctx.rng.integers(65536)), False: int(ctx.rng.integers(65536))}
    for i, (t, up, size) in enumerate(_times(spec)):
        n = max(size - ov, 1)
        payload = codec(state, r, up, i, n, t, spec.domain or "example.net") if codec else protocols.opaque_bytes(r, n)
        ident[up] += 1
        out.append((t, up, _udp_pkt(ctx, spec.server_port, up, payload, ident[up])))
    return out


def dns_lookup(ctx: Ctx, resolver: bytes, name: str, answer: bytes, t: float) -> tuple[list[Pkt], float]:
    """UE asks the resolver for `name`, gets `answer`; returns packets and the time of the reply."""
    qtype = 1 if len(answer) == 4 else 28
    qid = int(ctx.rng.integers(65536))
    sport = int(ctx.rng.integers(32768, 61000))
    src = ctx.ue_ip
    q = P.dns_query(qid, name, qtype)
    r = P.dns_response(qid, name, qtype, [answer], int(ctx.rng.integers(60, 600)))
    t_r = t + ctx.ms(8, 45)
    ident = int(ctx.rng.integers(65536))
    up = P.ip_packet(src, resolver, 17, P.udp(src, resolver, sport, 53, q), ident=ident)
    down = P.ip_packet(resolver, src, 17, P.udp(resolver, src, 53, sport, r), ident=ident + 7, ttl=58)
    return [(t, True, up), (t_r, False, down)], t_r
