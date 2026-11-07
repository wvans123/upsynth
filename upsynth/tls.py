"""TLS ClientHello parsing, JA4 fingerprints, and hello builders for synthesis.

JA4 follows the FoxIO specification: t13d1516h2_<sha256(sorted ciphers)[:12]>_<sha256(sorted
extensions without SNI/ALPN + "_" + signature algorithms in order)[:12]>. GREASE values are ignored.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass, field

TLS_VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
                0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3"}
VERSION_CODES = {v: k for k, v in TLS_VERSIONS.items()}

EXT_SNI = 0x0000
EXT_ALPN = 0x0010
EXT_SIGALGS = 0x000D
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_QUIC_TP = 0x0039


def is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


@dataclass
class ClientHello:
    legacy_version: int
    ciphers: list[int]
    extensions: list[int]  # in wire order
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    sigalgs: list[int] = field(default_factory=list)
    versions: list[int] = field(default_factory=list)


def parse_client_hello(msg: bytes) -> ClientHello | None:
    """Parse a handshake message (starting with type 0x01). Returns None if it is not a full ClientHello."""
    try:
        if len(msg) < 4 or msg[0] != 1:
            return None
        n = int.from_bytes(msg[1:4], "big")
        b = msg[4 : 4 + n]
        if len(b) < n:
            return None
        p = 0
        legacy = struct.unpack_from("!H", b, p)[0]
        p += 2 + 32
        p += 1 + b[p]
        cl = struct.unpack_from("!H", b, p)[0]
        p += 2
        ciphers = [struct.unpack_from("!H", b, p + i)[0] for i in range(0, cl, 2)]
        p += cl
        p += 1 + b[p]
        ch = ClientHello(legacy, ciphers, [])
        if p + 2 > len(b):
            return ch
        el = struct.unpack_from("!H", b, p)[0]
        p += 2
        end = min(p + el, len(b))
        while p + 4 <= end:
            et, ln = struct.unpack_from("!HH", b, p)
            p += 4
            d = b[p : p + ln]
            p += ln
            ch.extensions.append(et)
            if et == EXT_SNI and len(d) >= 5:
                nl = struct.unpack_from("!H", d, 3)[0]
                ch.sni = d[5 : 5 + nl].decode("ascii", "replace").lower()
            elif et == EXT_ALPN and len(d) >= 2:
                q = 2
                while q < len(d):
                    ln1 = d[q]
                    ch.alpn.append(d[q + 1 : q + 1 + ln1].decode("ascii", "replace"))
                    q += 1 + ln1
            elif et == EXT_SIGALGS and len(d) >= 2:
                sl = struct.unpack_from("!H", d, 0)[0]
                ch.sigalgs = [struct.unpack_from("!H", d, 2 + i)[0] for i in range(0, min(sl, len(d) - 2), 2)]
            elif et == EXT_SUPPORTED_VERSIONS and len(d) >= 1:
                ch.versions = [struct.unpack_from("!H", d, 1 + i)[0] for i in range(0, min(d[0], len(d) - 1), 2)]
        return ch
    except (struct.error, IndexError):
        return None


def handshake_from_records(stream: bytes) -> bytes | None:
    """Concatenate handshake-record fragments from the start of a TLS byte stream.

    Returns the first handshake message once it is complete, None if more bytes are needed or the
    stream is not TLS.
    """
    hs = b""
    p = 0
    while p + 5 <= len(stream):
        ctype, ver, ln = struct.unpack_from("!BHH", stream, p)
        if ctype != 22 or (ver >> 8) != 3:
            return None if not hs else _complete(hs)
        hs += stream[p + 5 : p + 5 + ln]
        p += 5 + ln
        done = _complete(hs)
        if done:
            return done
    return None


def _complete(hs: bytes) -> bytes | None:
    if len(hs) >= 4:
        n = int.from_bytes(hs[1:4], "big")
        if len(hs) >= 4 + n:
            return hs[: 4 + n]
    return None


def looks_like_tls(stream: bytes) -> bool:
    return len(stream) >= 6 and stream[0] == 22 and stream[1] == 3 and stream[5] == 1


def _alpn_chars(alpn: list[str]) -> str:
    if not alpn or not alpn[0]:
        return "00"
    a = alpn[0]
    f, l = a[0], a[-1]
    if f.isascii() and f.isalnum() and l.isascii() and l.isalnum():
        return f + l
    h = a.encode().hex()
    return h[0] + h[-1]


def _hash12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12] if s else "000000000000"


def ja4(ch: ClientHello, transport: str = "t") -> tuple[str, str]:
    """Return (ja4, ja4_r). transport is "t" for TCP, "q" for QUIC."""
    ciphers = [c for c in ch.ciphers if not is_grease(c)]
    exts = [e for e in ch.extensions if not is_grease(e)]
    versions = [v for v in ch.versions if not is_grease(v)]
    ver = TLS_VERSIONS.get(max(versions) if versions else ch.legacy_version, "00")
    sni = "d" if EXT_SNI in exts else "i"
    a = f"{transport}{ver}{sni}{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{_alpn_chars(ch.alpn)}"
    sc = ",".join(f"{c:04x}" for c in sorted(ciphers))
    se = ",".join(f"{e:04x}" for e in sorted(e for e in exts if e not in (EXT_SNI, EXT_ALPN)))
    sg = ",".join(f"{s:04x}" for s in ch.sigalgs if not is_grease(s))
    ext_str = se + ("_" + sg if sg else "")
    return f"{a}_{_hash12(sc)}_{_hash12(ext_str) if se else '000000000000'}", f"{a}_{sc}_{se}" + (f"_{sg}" if sg else "")


def normalize_raw(ja4_r: str) -> str:
    """Make the cipher / extension counts in the prefix agree with the lists (SNI and ALPN count too)."""
    parts = ja4_r.split("_")
    p = parts[0]
    if len(p) != 10 or len(parts) < 3:
        return ja4_r
    nc = len([c for c in parts[1].split(",") if c])
    ne = len([e for e in parts[2].split(",") if e]) + (p[3] == "d") + (p[8:10] != "00")
    return f"{p[:4]}{min(nc, 99):02d}{min(ne, 99):02d}{p[8:]}_" + "_".join(parts[1:])


def ja4_from_raw(ja4_r: str) -> str:
    parts = ja4_r.split("_")
    sc = parts[1] if len(parts) > 1 else ""
    se = parts[2] if len(parts) > 2 else ""
    sg = parts[3] if len(parts) > 3 else ""
    return f"{parts[0]}_{_hash12(sc)}_{_hash12(se + ('_' + sg if sg else '')) if se else '000000000000'}"


# ---------------------------------------------------------------- builders

CHROME_JA4_R = (
    "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_"
    "0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_"
    "0403,0804,0401,0503,0805,0501,0806,0601"
)
CHROME_QUIC_JA4_R = (
    "q13d0313h3_1301,1302,1303_0005,000a,000d,001b,0029,002b,002d,0033,0039,44cd,fe0d_"
    "0403,0804,0401,0503,0805,0501,0806,0601"
)

DEFAULT_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def _u16list(vals: list[int]) -> bytes:
    body = b"".join(struct.pack("!H", v) for v in vals)
    return struct.pack("!H", len(body)) + body


def _varint(v: int) -> bytes:
    if v < 0x40:
        return bytes([v])
    if v < 0x4000:
        return struct.pack("!H", v | 0x4000)
    if v < 0x40000000:
        return struct.pack("!I", v | 0x80000000)
    return struct.pack("!Q", v | 0xC000000000000000)


def quic_transport_params(scid: bytes, rnd) -> bytes:
    def tp(i: int, val: bytes) -> bytes:
        return _varint(i) + _varint(len(val)) + val

    out = tp(0x01, _varint(30000))  # max_idle_timeout
    out += tp(0x03, _varint(1472))  # max_udp_payload_size
    out += tp(0x04, _varint(15728640))  # initial_max_data
    out += tp(0x05, _varint(6291456))
    out += tp(0x06, _varint(6291456))
    out += tp(0x07, _varint(6291456))
    out += tp(0x08, _varint(100))
    out += tp(0x09, _varint(103))
    out += tp(0x0E, _varint(4))  # active_connection_id_limit
    out += tp(0x0F, scid)  # initial_source_connection_id
    return out


def _ext_body(et: int, *, sni, alpn, sigalgs, version, pq, quic_scid, rnd) -> bytes:
    if et == EXT_SNI:
        name = sni.encode()
        return struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    if et == EXT_ALPN:
        body = b"".join(bytes([len(a)]) + a.encode() for a in alpn)
        return struct.pack("!H", len(body)) + body
    if et == 0x0005:
        return b"\x01\x00\x00\x00\x00"
    if et == 0x000A:
        return _u16list(([0x11EC] if pq else []) + [0x001D, 0x0017, 0x0018])
    if et == 0x000B:
        return b"\x01\x00"
    if et in (0x000D, 0x0032):
        return _u16list(sigalgs or DEFAULT_SIGALGS)
    if et == 0x001B:
        return b"\x02\x00\x02"
    if et == 0x001C:
        return b"\x40\x01"
    if et == 0x0022:
        return _u16list([0x0403, 0x0503, 0x0603, 0x0203])
    if et == 0x0029:
        ident = rnd(rnd_len(rnd, 160, 200))
        identities = struct.pack("!H", len(ident)) + ident + rnd(4)
        binders = b"\x20" + rnd(32)
        return struct.pack("!H", len(identities)) + identities + struct.pack("!H", len(binders)) + binders
    if et == EXT_SUPPORTED_VERSIONS:
        vers = [0x0304, 0x0303] if version == "13" else [VERSION_CODES.get(version, 0x0303)]
        body = b"".join(struct.pack("!H", v) for v in vers)
        return bytes([len(body)]) + body
    if et == 0x002D:
        return b"\x01\x01"
    if et == 0x0033:
        shares = b""
        if pq:
            shares += struct.pack("!HH", 0x11EC, 1216) + rnd(1216)
        shares += struct.pack("!HH", 0x001D, 32) + rnd(32)
        return struct.pack("!H", len(shares)) + shares
    if et == EXT_QUIC_TP:
        return quic_transport_params(quic_scid or rnd(8), rnd)
    if et in (0x4469, 0x44CD):
        proto = b"h2" if not quic_scid else b"h3"
        return struct.pack("!HB", len(proto) + 1, len(proto)) + proto
    if et == 0xFE0D:
        payload = rnd(rnd_len(rnd, 144, 240))
        return b"\x00\x00\x01\x00\x01" + rnd(1) + struct.pack("!H", 32) + rnd(32) + struct.pack("!H", len(payload)) + payload
    if et == 0xFF01:
        return b"\x00"
    if et == 0x0001:
        return b"\x04"
    if et == 0x0015:
        return bytes(rnd_len(rnd, 0, 200))
    return b""


def rnd_len(rnd, lo: int, hi: int) -> int:
    return lo + int.from_bytes(rnd(2), "big") % (hi - lo + 1)


def build_client_hello(ja4_r: str, sni: str | None, alpn: list[str], *, quic_scid: bytes | None = None,
                       rnd=os.urandom) -> bytes:
    """Build a ClientHello handshake message whose JA4 equals the JA4 of ja4_r.

    The raw form keeps sorted cipher and extension lists, so their order is free; the TLS 1.3 suites
    go first and pre_shared_key last as real clients do.
    """
    parts = ja4_r.split("_")
    prefix = parts[0]
    ciphers = [int(c, 16) for c in parts[1].split(",") if c] if len(parts) > 1 else []
    exts = [int(e, 16) for e in parts[2].split(",") if e] if len(parts) > 2 else []
    sigalgs = [int(s, 16) for s in parts[3].split(",") if s] if len(parts) > 3 else []
    version = prefix[1:3]
    has_sni = prefix[3] == "d"
    has_alpn = prefix[8:10] != "00"
    if has_sni and not sni:
        sni = "example.com"
    if has_alpn and not alpn:
        alpn = ["h3"] if quic_scid else ["h2", "http/1.1"]
    pq = 0x44CD in exts or 0x4469 in exts
    ciphers.sort(key=lambda c: (0 if 0x1301 <= c <= 0x1303 else 1, c))
    order = ([EXT_SNI] if has_sni else []) + [e for e in exts if e != 0x0029]
    if has_alpn:
        order.insert(min(len(order), 3), EXT_ALPN)
    if 0x0029 in exts:
        order.append(0x0029)
    ext_bytes = b""
    for et in order:
        body = _ext_body(et, sni=sni, alpn=alpn, sigalgs=sigalgs, version=version, pq=pq,
                         quic_scid=quic_scid, rnd=rnd)
        ext_bytes += struct.pack("!HH", et, len(body)) + body
    legacy = 0x0303 if version in ("13", "12") else VERSION_CODES.get(version, 0x0303)
    session_id = b"" if quic_scid is not None else rnd(32)
    comp = b"\x01\x00"
    body = (struct.pack("!H", legacy) + rnd(32) + bytes([len(session_id)]) + session_id
            + struct.pack("!H", 2 * len(ciphers)) + b"".join(struct.pack("!H", c) for c in ciphers)
            + comp + struct.pack("!H", len(ext_bytes)) + ext_bytes)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def build_server_hello(*, tls13: bool = True, session_id: bytes = b"", cipher: int = 0x1301, rnd=os.urandom) -> bytes:
    exts = b""
    if tls13:
        exts += struct.pack("!HHH", EXT_SUPPORTED_VERSIONS, 2, 0x0304)
        exts += struct.pack("!HHHH", 0x0033, 36, 0x001D, 32) + rnd(32)
    body = (b"\x03\x03" + rnd(32) + bytes([len(session_id)]) + session_id + struct.pack("!H", cipher)
            + b"\x00" + struct.pack("!H", len(exts)) + exts)
    return b"\x02" + len(body).to_bytes(3, "big") + body


def record(ctype: int, payload: bytes, version: int = 0x0303) -> bytes:
    return struct.pack("!BHH", ctype, version, len(payload)) + payload


def session_id_of(client_hello: bytes) -> bytes:
    n = client_hello[4 + 2 + 32]
    return client_hello[4 + 2 + 32 + 1 : 4 + 2 + 32 + 1 + n]
