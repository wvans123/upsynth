"""Byte-level builders: Ethernet, IPv4/IPv6, TCP, UDP, GTP-U with PDU Session Container, DNS, pcap."""

from __future__ import annotations

import struct
from typing import BinaryIO

ETH_IP4, ETH_IP6 = 0x0800, 0x86DD


def _fold(s: int) -> int:
    r = s % 0xFFFF
    return 0xFFFF if r == 0 and s else r


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    return ~_fold(int.from_bytes(data, "big")) & 0xFFFF


def _pseudo(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    if len(src) == 4:
        return src + dst + struct.pack("!BBH", 0, proto, length)
    return src + dst + struct.pack("!IxxxB", length, proto)


def _l4_checksum(src: bytes, dst: bytes, proto: int, seg: bytes) -> int:
    data = _pseudo(src, dst, proto, len(seg)) + seg
    if len(data) % 2:
        data += b"\x00"
    c = ~_fold(int.from_bytes(data, "big")) & 0xFFFF
    return 0xFFFF if c == 0 and proto == 17 else c


def ip_packet(src: bytes, dst: bytes, proto: int, l4: bytes, *, ident: int = 0, ttl: int = 64) -> bytes:
    if len(src) == 4:
        h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), ident & 0xFFFF, 0x4000, ttl, proto, 0, src, dst)
        return h[:10] + struct.pack("!H", checksum(h)) + h[12:] + l4
    return struct.pack("!IHBB", 0x60000000, len(l4), proto, ttl) + src + dst + l4


def ip_header_len(src: bytes) -> int:
    return 20 if len(src) == 4 else 40


def udp(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes, *, csum: bool = True) -> bytes:
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    if not csum and len(src) == 4:
        return seg
    c = _l4_checksum(src, dst, 17, seg)
    return seg[:6] + struct.pack("!H", c) + seg[8:]


TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10
TCP_TS_HDR = 32  # header with the timestamps option, used on every non-SYN segment


def tcp(src: bytes, dst: bytes, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"", *,
        window: int = 2048, tsval: int = 0, tsecr: int = 0, syn_mss: int = 1460) -> bytes:
    if flags & TCP_SYN:
        opts = struct.pack("!BBH", 2, 4, syn_mss) + b"\x04\x02" + struct.pack("!BBII", 8, 10, tsval, tsecr) + b"\x01\x03\x03\x07"
        window = 65535
    else:
        opts = b"\x01\x01" + struct.pack("!BBII", 8, 10, tsval, tsecr)
    off = (20 + len(opts)) // 4
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, off << 4, flags, window, 0, 0) + opts + payload
    c = _l4_checksum(src, dst, 6, seg)
    return seg[:16] + struct.pack("!H", c) + seg[18:]


def gtpu(teid: int, inner: bytes, *, qfi: int, uplink: bool) -> bytes:
    """G-PDU with a PDU Session Container (TS 38.415): UL PDU type 1, DL PDU type 0."""
    ext = bytes([1, 0x10 if uplink else 0x00, qfi & 0x3F, 0])
    body = struct.pack("!HBB", 0, 0, 0x85) + ext + inner
    return struct.pack("!BBHI", 0x34, 0xFF, len(body), teid) + body


def ethernet(src_mac: bytes, dst_mac: bytes, l3: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", ETH_IP4 if l3[0] >> 4 == 4 else ETH_IP6) + l3


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        lb = label.encode("idna") if not label.isascii() else label.encode()
        out += bytes([len(lb)]) + lb
    return out + b"\x00"


def dns_query(qid: int, name: str, qtype: int) -> bytes:
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(qid: int, name: str, qtype: int, answers: list[bytes], ttl: int) -> bytes:
    msg = struct.pack("!HHHHHH", qid, 0x8180, 1, len(answers), 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)
    for a in answers:
        msg += struct.pack("!HHHIH", 0xC00C, qtype, 1, ttl, len(a)) + a
    return msg


class PcapWriter:
    """Classic pcap, microsecond timestamps, Ethernet link type."""

    def __init__(self, f: BinaryIO, linktype: int = 1, snaplen: int = 262144):
        self.f = f
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        self.count = 0

    def write(self, ts: float, frame: bytes) -> None:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)
        self.count += 1
