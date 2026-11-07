"""Payload codecs for well-known ports, so Wireshark's port-registered dissectors see valid messages.

A TCP codec turns one burst (consecutive data from one side) into a byte string of about the wanted
size; the template then sizes the TCP segments to exactly that string. A UDP codec returns one
datagram payload. Encrypted protocols carry random bytes only where the real protocol has
ciphertext.
"""

from __future__ import annotations

import hashlib
import struct
import subprocess
from importlib import resources
from typing import Callable

import numpy as np

# TCP ports where the stream is TLS from the first byte; an opaque "tcp" flow there becomes tls_tcp
TLS_TCP_PORTS = {443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 5061, 5223, 5228, 5349, 6697, 8443, 8801,
                 8802, 8883}


class Rnd:
    def __init__(self, rng: np.random.Generator):
        self.rng = rng

    def bytes(self, n: int) -> bytes:
        return self.rng.bytes(n) if n > 0 else b""

    def int(self, lo: int, hi: int) -> int:
        return int(self.rng.integers(lo, hi))


# ---------------------------------------------------------------- TCP stream codecs
# signature: (state, rnd, up, index_in_direction, wanted_bytes, host) -> bytes

TcpCodec = Callable[[dict, Rnd, bool, int, int, str], bytes]


def http(state: dict, r: Rnd, up: bool, idx: int, n: int, host: str) -> bytes:
    if up:
        req = (f"GET /{r.bytes(6).hex()} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Linux; Android 14)\r\n"
               f"Accept: */*\r\nConnection: keep-alive\r\n").encode()
        pad = n - len(req) - 2 - 9
        if pad > 0:
            req += b"X-Pad: " + r.bytes(pad // 2 + 1).hex()[:pad].encode() + b"\r\n"
        return req + b"\r\n"
    head = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n"
    body = _fit_body(head, n)
    return head % body + r.bytes(body)


def _fit_body(head: bytes, total: int) -> int:
    for digits in range(1, 12):
        body = total - (len(head) - 2 + digits)
        if body >= 0 and len(str(body)) == digits:
            return body
    return 0


def _mqtt(ptype_flags: int, body: bytes) -> bytes:
    n = len(body)
    rl = b""
    while True:
        b = n % 128
        n //= 128
        rl += bytes([b | (0x80 if n else 0)])
        if not n:
            break
    return bytes([ptype_flags]) + rl + body


def _rl_len(v: int) -> int:
    return 1 if v < 128 else 2 if v < 16384 else 3 if v < 2097152 else 4


def _mqtt_publish_fill(r: Rnd, n: int) -> bytes:
    out = b""
    while n - len(out) >= 12:
        total = min(n - len(out), 65536)
        topic = b"t/" + r.bytes(3).hex().encode()
        rl = next((total - 1 - k for k in (1, 2, 3) if _rl_len(total - 1 - k) == k), total - 3)
        out += _mqtt(0x30, struct.pack("!H", len(topic)) + topic + r.bytes(rl - 2 - len(topic)))
    while n - len(out) >= 2:
        out += b"\xc0\x00"  # PINGREQ
    return out


def mqtt(state: dict, r: Rnd, up: bool, idx: int, n: int, host: str) -> bytes:
    if up and idx == 0:
        cid = b"c" + r.bytes(8).hex().encode()
        msg = _mqtt(0x10, b"\x00\x04MQTT\x04\x02\x00\x3c" + struct.pack("!H", len(cid)) + cid)
    elif not up and idx == 0:
        msg = b"\x20\x02\x00\x00"
    else:
        msg = b""
    return msg + _mqtt_publish_fill(r, max(n - len(msg), 0 if msg else 2))


def _sip(r: Rnd, up: bool, n: int, host: str, state: dict) -> bytes:
    if "call" not in state:
        state["call"] = r.bytes(8).hex()
        state["cseq"] = 1
    state["cseq"] += up
    tag = state["call"][:6]
    if up:
        first = f"OPTIONS sip:{host} SIP/2.0\r\n"
        via = f"Via: SIP/2.0/UDP 10.45.0.2:5060;branch=z9hG4bK{r.bytes(4).hex()}\r\n"
    else:
        first = "SIP/2.0 200 OK\r\n"
        via = f"Via: SIP/2.0/UDP 10.45.0.2:5060;branch=z9hG4bK{r.bytes(4).hex()}\r\n"
    msg = (first + via + f"From: <sip:ue@{host}>;tag={tag}\r\nTo: <sip:{host}>\r\nCall-ID: {state['call']}\r\n"
           f"CSeq: {state['cseq']} OPTIONS\r\nMax-Forwards: 70\r\n").encode()
    pad = n - len(msg) - 19 - 11
    if pad > 0:
        msg += b"X-Pad: " + r.bytes(pad // 2 + 1).hex()[:pad].encode() + b"\r\n"
    return msg + b"Content-Length: 0\r\n\r\n"


def sip_tcp(state: dict, r: Rnd, up: bool, idx: int, n: int, host: str) -> bytes:
    return _sip(r, up, n, host, state)


def _rtmp_msgs(r: Rnd, n: int) -> bytes:
    out = b""
    while n - len(out) >= 17:
        left = min(n - len(out), 60000)
        payload = max(left - 12, 5)
        out += bytes([0x06]) + struct.pack("!I", 0)[1:] + struct.pack("!I", payload)[1:] + b"\x09" + b"\x01\x00\x00\x00"
        out += b"\x27\x01\x00\x00\x00" + r.bytes(payload - 5)  # FLV video tag: inter frame, AVC NALU
    return out


def rtmp(state: dict, r: Rnd, up: bool, idx: int, n: int, host: str) -> bytes:
    set_chunk = bytes([0x02]) + b"\x00\x00\x00" + struct.pack("!I", 4)[1:] + b"\x01" + b"\x00\x00\x00\x00" + struct.pack("!I", 65536)
    if idx == 0:
        return (b"\x03" + struct.pack("!I", 0) + bytes(4) + r.bytes(1528)) if up else \
            (b"\x03" + struct.pack("!I", 0) + bytes(4) + r.bytes(1528) + struct.pack("!I", 0) + bytes(4) + r.bytes(1528))
    head = b""
    if idx == 1:
        head = (struct.pack("!I", 0) + bytes(4) + r.bytes(1528)) if up else b""
        head += set_chunk
    return head + _rtmp_msgs(r, max(n - len(head), 17))


def opaque_bytes(r: Rnd, n: int) -> bytes:
    """Random bytes whose first byte (0xC0-0xFF) no heuristic dissector claims (RTP/RTCP, STUN, DTLS, WireGuard
    want other leading bits; a QUIC long header would also need a known version)."""
    n = max(n, 1)
    first = 0xC0 | r.int(0, 64)
    return bytes([first if first != 0xED else 0xEE]) + r.bytes(n - 1)  # 0xED leads a Pathport header


def opaque(state: dict, r: Rnd, up: bool, idx: int, n: int, host: str) -> bytes:
    return opaque_bytes(r, n)


TCP_CODECS: dict[int, TcpCodec] = {80: http, 8080: http, 8000: http, 1883: mqtt, 5060: sip_tcp, 1935: rtmp}


def client_speaks_first(port: int) -> bool:
    return port in (80, 8080, 8000, 1883, 5060, 1935)


# ---------------------------------------------------------------- UDP datagram codecs
# signature: (state, rnd, up, index_in_flow, wanted_bytes, t, host) -> bytes

UdpCodec = Callable[[dict, Rnd, bool, int, int, float, str], bytes]
NTP_EPOCH = 2208988800


def ntp(state, r: Rnd, up, i, n, t, host) -> bytes:
    now = struct.pack("!II", (int(t) + NTP_EPOCH) & 0xFFFFFFFF, int((t % 1) * 2**32))
    if up:
        return b"\x23" + bytes(39) + now
    ref = struct.pack("!II", (int(t) - 30 + NTP_EPOCH) & 0xFFFFFFFF, 0)
    return b"\x24\x02\x03\xe9" + struct.pack("!II", 0x0300, 0x0400) + b"\xc6\x12\x00\x01" + ref + r.bytes(8) + now + now


def rtp(state, r: Rnd, up, i, n, t, host) -> bytes:
    s = state.setdefault(up, {"seq": r.int(0, 65536), "ts": r.int(0, 2**32), "ssrc": r.int(1, 2**32)})
    s["seq"] = (s["seq"] + 1) & 0xFFFF
    s["ts"] = (s["ts"] + 960) & 0xFFFFFFFF
    return struct.pack("!BBHII", 0x80, 111, s["seq"], s["ts"], s["ssrc"]) + r.bytes(max(n - 12, 1))


def stun_or_rtp(state, r: Rnd, up, i, n, t, host) -> bytes:
    """ICE connectivity checks first (STUN Binding), then SRTP-shaped media."""
    if i < 2:
        tid = state.setdefault("tid", r.bytes(12))
        if up:
            return struct.pack("!HHI", 0x0001, 0, 0x2112A442) + tid
        xaddr = struct.pack("!BBH", 0, 1, 0xC001 ^ 0x2112) + bytes(a ^ b for a, b in zip(b"\x0a\x2d\x00\x02", b"\x21\x12\xa4\x42"))
        attr = struct.pack("!HH", 0x0020, len(xaddr)) + xaddr
        return struct.pack("!HHI", 0x0101, len(attr), 0x2112A442) + tid + attr
    return rtp(state, r, up, i, n, t, host)


def wireguard(state, r: Rnd, up, i, n, t, host) -> bytes:
    idx = state.setdefault("idx", {True: r.int(1, 2**32), False: r.int(1, 2**32)})
    if i == 0 and up:
        return struct.pack("<B3xI", 1, idx[True]) + r.bytes(140)
    if not state.get("resp") and not up:
        state["resp"] = True
        return struct.pack("<B3xII", 2, idx[False], idx[True]) + r.bytes(84)
    ctr = state.setdefault("ctr", {True: 0, False: 0})
    ctr[up] += 1
    body = max(((n - 32) // 16) * 16, 0) + 16
    return struct.pack("<B3xIQ", 4, idx[not up], ctr[up]) + r.bytes(body)


def openvpn(state, r: Rnd, up, i, n, t, host) -> bytes:
    sid = state.setdefault("sid", {True: r.bytes(8), False: r.bytes(8)})
    if i == 0 and up:
        return b"\x38" + sid[True] + b"\x00" + struct.pack("!I", 0)
    if not state.get("resp") and not up:
        state["resp"] = True
        return b"\x40" + sid[False] + b"\x01" + struct.pack("!I", 0) + sid[True] + struct.pack("!I", 0)
    return b"\x48" + struct.pack("!I", r.int(0, 2**24))[1:] + r.bytes(max(n - 4, 16))


def ike(state, r: Rnd, up, i, n, t, host) -> bytes:
    spi = state.setdefault("spi", {True: r.bytes(8), False: r.bytes(8)})
    msg_id = state.setdefault("msg", 0)
    if i < 2:
        exch, nxt = 34, 40
        body = struct.pack("!BBH", 0, 0, 4 + 32) + r.bytes(32)  # Nonce payload
    else:
        exch, nxt = 35, 46
        if up:
            state["msg"] = msg_id = msg_id + 1
        enc = r.bytes(max(n - 28 - 4, 48))
        body = struct.pack("!BBH", 35, 0, 4 + len(enc)) + enc  # Encrypted and Authenticated payload
    flags = 0x08 if up else 0x20
    resp_spi = spi[False] if i >= 1 else bytes(8)
    hdr = spi[True] + resp_spi + struct.pack("!BBBBII", nxt, 0x20, exch, flags, msg_id, 28 + len(body))
    return hdr + body


def esp(state, r: Rnd, up, i, n, t, host) -> bytes:
    spi = state.setdefault("spi", {True: r.int(256, 2**32), False: r.int(256, 2**32)})
    seq = state.setdefault("seq", {True: 0, False: 0})
    seq[up] += 1
    return struct.pack("!II", spi[up], seq[up]) + r.bytes(max(n - 8, 16))


def dns(state, r: Rnd, up, i, n, t, host) -> bytes:
    qid = state.setdefault("id", r.int(0, 65536))
    name = b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\x00"
    q = struct.pack("!HHHHHH", qid, 0x0100 if up else 0x8180, 1, 0 if up else 1, 0, 0) + name + b"\x00\x01\x00\x01"
    return q if up else q + struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + b"\xc6\x12\x00\x01"


def sip_udp(state, r: Rnd, up, i, n, t, host) -> bytes:
    return _sip(r, up, n, host, state)


UDP_CODECS: dict[int, UdpCodec] = {53: dns, 123: ntp, 500: ike, 1194: openvpn, 4500: esp, 5060: sip_udp,
                                   51820: wireguard}
for _p in list(range(3478, 3498)) + list(range(19302, 19310)) + [5349]:
    UDP_CODECS[_p] = stun_or_rtp


# ---------------------------------------------------------------- Wireshark port registry

TLS_FRIENDLY = {"tls", "http"}


def load_registry(tshark: str | None = None) -> dict[tuple[str, int], str]:
    """(proto, port) -> dissector Wireshark binds to that port: the bundled snapshot plus the local tshark."""
    reg: dict[tuple[str, int], str] = {}
    lines = resources.files("upsynth.synth").joinpath("wireshark_ports.tsv").read_text(encoding="utf-8").splitlines()
    if tshark:
        try:
            out = subprocess.run([tshark, "-G", "decodes"], capture_output=True, text=True, timeout=60).stdout
            lines += [l.replace(".port", "", 1) for l in out.splitlines() if l.startswith(("tcp.port", "udp.port"))]
        except (OSError, subprocess.SubprocessError):
            pass
    for line in lines:
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] in ("tcp", "udp") and parts[1].isdigit():
            reg[(parts[0], int(parts[1]))] = parts[2]
    return reg


def fits(transport: str, port: int, reg: dict[tuple[str, int], str]) -> bool:
    """True if Wireshark's dissector on this port accepts what the template writes."""
    d = reg.get(("udp" if transport in ("udp", "quic") else "tcp", port))
    if d is None:
        return True
    if transport == "quic":
        return d == "quic"
    if transport == "tls_tcp":
        return port in TLS_TCP_PORTS or d in TLS_FRIENDLY
    if transport == "tcp":
        return port in TCP_CODECS
    return port in UDP_CODECS


def free_port(transport: str, port: int, reg: dict[tuple[str, int], str]) -> int:
    proto = "udp" if transport in ("udp", "quic") else "tcp"
    h = int(hashlib.sha256(f"{proto}/{port}".encode()).hexdigest()[:8], 16)
    for i in range(40000):
        cand = 20000 + (h + i * 7919) % 40000
        if (proto, cand) not in reg:
            return cand
    return port
