"""Read pcap / pcapng and decode down to the user's IP packet, unwrapping GTP-U on N3.

dpkt reads the files and link layers; IP, UDP, TCP and GTP-U are decoded by hand because only a
few fields are needed and this is the hot loop.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

import dpkt

GTPU_PORT = 2152

_PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


@dataclass(slots=True)
class Packet:
    ts: float
    ver: int
    src: bytes
    dst: bytes
    proto: int
    sport: int
    dport: int
    ip_len: int
    tcp_flags: int
    tcp_seq: int
    payload: bytes
    teid: int | None = None
    qfi: int | None = None
    pdu_type: int | None = None  # 0 downlink, 1 uplink (PDU Session Container), None if absent


@dataclass
class ReadStats:
    frames: int = 0
    ip: int = 0
    gtpu: int = 0
    gtpu_other: int = 0  # echo, end marker, error indication
    non_ip: int = 0
    other_l4: int = 0
    fragments: int = 0
    truncated: int = 0


def open_reader(f: BinaryIO):
    magic = f.read(4)
    f.seek(0)
    if magic in _PCAP_MAGICS:
        return dpkt.pcap.Reader(f)
    if magic == _PCAPNG_MAGIC:
        return dpkt.pcapng.Reader(f)
    raise ValueError("not a pcap or pcapng file")


def _l3_from_link(dlt: int, buf: bytes) -> bytes | None:
    if dlt == dpkt.pcap.DLT_EN10MB:
        p = 12
        etype = struct.unpack_from("!H", buf, p)[0]
        while etype in (0x8100, 0x88A8, 0x9100):
            p += 4
            etype = struct.unpack_from("!H", buf, p)[0]
        if etype == 0x8847:  # MPLS unicast: skip labels until bottom of stack
            q = p + 2
            while q + 4 <= len(buf):
                bos = buf[q + 2] & 1
                q += 4
                if bos:
                    break
            return buf[q:]
        if etype in (0x0800, 0x86DD):
            return buf[p + 2 :]
        return None
    if dlt in (101, 12, 14, 228, 229):  # LINKTYPE_RAW and the platform DLT_RAW values, IPv4, IPv6
        return buf
    if dlt == 113:  # Linux cooked v1
        return buf[16:] if struct.unpack_from("!H", buf, 14)[0] in (0x0800, 0x86DD) else None
    if dlt == 276:  # Linux cooked v2
        return buf[20:] if struct.unpack_from("!H", buf, 0)[0] in (0x0800, 0x86DD) else None
    if dlt in (0, 108):  # BSD loopback: 4-byte address family in host or network order
        return buf[4:]
    return None


def _ip(buf: bytes, stats: ReadStats):
    """Return (ver, src, dst, proto, l4 bytes, ip_len) or None."""
    if not buf:
        return None
    v = buf[0] >> 4
    if v == 4:
        if len(buf) < 20:
            return None
        ihl = (buf[0] & 0x0F) * 4
        total = struct.unpack_from("!H", buf, 2)[0]
        frag = struct.unpack_from("!H", buf, 6)[0]
        if frag & 0x1FFF:
            stats.fragments += 1
            return None
        if frag & 0x2000:
            stats.fragments += 1
        return 4, buf[12:16], buf[16:20], buf[9], buf[ihl:total] if total >= ihl else buf[ihl:], total or len(buf)
    if v == 6:
        if len(buf) < 40:
            return None
        plen = struct.unpack_from("!H", buf, 4)[0]
        nh = buf[6]
        p = 40
        while nh in (0, 43, 60, 44):
            if p + 8 > len(buf):
                return None
            if nh == 44:
                if struct.unpack_from("!H", buf, p + 2)[0] & 0xFFF8:
                    stats.fragments += 1
                    return None
                nh, p = buf[p], p + 8
            else:
                nh, p = buf[p], p + (buf[p + 1] + 1) * 8
        return 6, buf[8:24], buf[24:40], nh, buf[p : 40 + plen] if plen else buf[p:], 40 + plen
    return None


def _gtpu(b: bytes):
    """Decode a G-PDU. Returns (teid, qfi, pdu_type, inner) or None for non G-PDU messages."""
    if len(b) < 8 or (b[0] >> 5) != 1 or b[1] != 0xFF:
        return None
    flags = b[0]
    teid = struct.unpack_from("!I", b, 4)[0]
    p = 8
    qfi = pdu_type = None
    if flags & 0x07:
        nxt = b[11]
        p = 12
        while nxt:
            ln = b[p] * 4
            if ln == 0 or p + ln > len(b):
                return None
            if nxt == 0x85 and ln >= 4:
                pdu_type = b[p + 1] >> 4
                qfi = b[p + 2] & 0x3F
            nxt = b[p + ln - 1]
            p += ln
    return teid, qfi, pdu_type, b[p:]


def _l4(ver, src, dst, proto, l4: bytes, ip_len: int, ts: float, stats: ReadStats) -> Packet | None:
    if proto == 6 and len(l4) >= 20:
        sport, dport, seq = struct.unpack_from("!HHI", l4, 0)
        off = (l4[12] >> 4) * 4
        return Packet(ts, ver, src, dst, 6, sport, dport, ip_len, l4[13], seq, l4[off:])
    if proto == 17 and len(l4) >= 8:
        sport, dport = struct.unpack_from("!HH", l4, 0)
        return Packet(ts, ver, src, dst, 17, sport, dport, ip_len, 0, 0, l4[8:])
    stats.other_l4 += 1
    return None


def iter_packets(path: str | Path, stats: ReadStats | None = None) -> Iterator[Packet]:
    """Yield user packets; on N3 the inner packet with TEID/QFI attached."""
    stats = stats if stats is not None else ReadStats()
    with open(path, "rb") as f:
        r = open_reader(f)
        dlt = r.datalink()
        for ts, buf in r:
            stats.frames += 1
            try:
                l3 = _l3_from_link(dlt, buf)
                ip = _ip(l3, stats) if l3 else None
            except (struct.error, IndexError):
                stats.truncated += 1
                continue
            if ip is None:
                stats.non_ip += 1
                continue
            stats.ip += 1
            ver, src, dst, proto, l4, ip_len = ip
            if proto == 17 and len(l4) >= 8:
                sport, dport = struct.unpack_from("!HH", l4, 0)
                if sport == GTPU_PORT or dport == GTPU_PORT:
                    try:
                        g = _gtpu(l4[8:])
                    except (struct.error, IndexError):
                        g = None
                    if g is None:
                        stats.gtpu_other += 1
                        continue
                    stats.gtpu += 1
                    teid, qfi, pdu_type, inner = g
                    iip = _ip(inner, stats)
                    if iip is None:
                        stats.non_ip += 1
                        continue
                    pkt = _l4(*iip, float(ts), stats)
                    if pkt is not None:
                        pkt.teid, pkt.qfi, pkt.pdu_type = teid, qfi, pdu_type
                        yield pkt
                    continue
            pkt = _l4(ver, src, dst, proto, l4, ip_len, float(ts), stats)
            if pkt is not None:
                yield pkt
