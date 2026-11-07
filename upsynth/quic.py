"""QUIC Initial packet protection (RFC 9001 section 5, RFC 9369 for v2).

Initial keys come from the client's first Destination Connection ID, so anyone on the path (and
Wireshark) can read the ClientHello inside. ingest uses this to get SNI, ALPN and JA4 from QUIC;
synth uses it to write Initials that Wireshark decrypts.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

V1 = 0x00000001
V2 = 0x6B3343CF

_SALT = {
    V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}
_LABELS = {V1: ("quic key", "quic iv", "quic hp"), V2: ("quicv2 key", "quicv2 iv", "quicv2 hp")}
# long header packet type bits per version: Initial, 0-RTT, Handshake, Retry
_TYPES = {V1: {0: "initial", 1: "0rtt", 2: "handshake", 3: "retry"},
          V2: {1: "initial", 2: "0rtt", 3: "handshake", 0: "retry"}}
_TYPE_BITS = {v: {name: bits for bits, name in m.items()} for v, m in _TYPES.items()}


def _expand_label(secret: bytes, label: str, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


@dataclass
class Keys:
    key: bytes
    iv: bytes
    hp: bytes


def initial_keys(dcid: bytes, version: int = V1) -> tuple[Keys, Keys]:
    """Return (client keys, server keys)."""
    initial = hmac.new(_SALT[version], dcid, hashlib.sha256).digest()
    out = []
    for side in ("client in", "server in"):
        s = _expand_label(initial, side, 32)
        k, iv, hp = _LABELS[version]
        out.append(Keys(_expand_label(s, k, 16), _expand_label(s, iv, 12), _expand_label(s, hp, 16)))
    return out[0], out[1]


def _hp_mask(hp: bytes, sample: bytes) -> bytes:
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    return enc.update(sample) + enc.finalize()


def read_varint(b: bytes, p: int) -> tuple[int, int]:
    first = b[p]
    n = 1 << (first >> 6)
    v = first & 0x3F
    for i in range(1, n):
        v = (v << 8) | b[p + i]
    return v, p + n


def varint(v: int) -> bytes:
    if v < 0x40:
        return bytes([v])
    if v < 0x4000:
        return struct.pack("!H", v | 0x4000)
    if v < 0x40000000:
        return struct.pack("!I", v | 0x80000000)
    return struct.pack("!Q", v | 0xC000000000000000)


@dataclass
class LongHeader:
    ptype: str
    version: int
    dcid: bytes
    scid: bytes
    payload: bytes | None  # decrypted frames (Initial only)
    size: int  # bytes this packet took in the datagram


def is_long_header(datagram: bytes) -> bool:
    return len(datagram) >= 7 and datagram[0] & 0xC0 == 0xC0


def parse_long(datagram: bytes, offset: int = 0, keys_dcid: bytes | None = None, from_client: bool = True) -> LongHeader | None:
    """Parse one long header packet; decrypt it if it is an Initial.

    keys_dcid: DCID the Initial keys derive from (the client's first DCID); defaults to this
    packet's DCID, right for the client's first flight.
    """
    b = datagram
    try:
        p = offset
        first = b[p]
        version = struct.unpack_from("!I", b, p + 1)[0]
        p += 5
        dl = b[p]
        dcid = b[p + 1 : p + 1 + dl]
        p += 1 + dl
        sl = b[p]
        scid = b[p + 1 : p + 1 + sl]
        p += 1 + sl
        if version not in _TYPES:
            return LongHeader("unknown", version, dcid, scid, None, len(b) - offset)
        ptype = _TYPES[version][(first >> 4) & 3]
        if ptype == "retry":
            return LongHeader(ptype, version, dcid, scid, None, len(b) - offset)
        if ptype == "initial":
            tl, p = read_varint(b, p)
            p += tl
        length, p = read_varint(b, p)
        pn_off = p
        size = pn_off + length - offset
        if ptype != "initial":
            return LongHeader(ptype, version, dcid, scid, None, size)
        ck, sk = initial_keys(keys_dcid if keys_dcid is not None else dcid, version)
        k = ck if from_client else sk
        sample = b[pn_off + 4 : pn_off + 20]
        if len(sample) < 16:
            return None
        mask = _hp_mask(k.hp, sample)
        f0 = first ^ (mask[0] & 0x0F)
        pn_len = (f0 & 3) + 1
        pn_bytes = bytes(x ^ y for x, y in zip(b[pn_off : pn_off + pn_len], mask[1 : 1 + pn_len]))
        header = bytes([f0]) + b[offset + 1 : pn_off] + pn_bytes
        pn = int.from_bytes(pn_bytes, "big")
        nonce = (int.from_bytes(k.iv, "big") ^ pn).to_bytes(12, "big")
        ct = b[pn_off + pn_len : pn_off + length]
        try:
            pt = AESGCM(k.key).decrypt(nonce, ct, header)
        except Exception:
            pt = None
        return LongHeader(ptype, version, dcid, scid, pt, size)
    except (IndexError, struct.error):
        return None


def crypto_frames(frames: bytes) -> list[tuple[int, bytes]]:
    """Return (offset, data) of every CRYPTO frame in a decrypted Initial payload."""
    out = []
    p = 0
    try:
        while p < len(frames):
            ft = frames[p]
            if ft == 0x00 or ft == 0x01:  # PADDING, PING
                p += 1
            elif ft in (0x02, 0x03):  # ACK
                p += 1
                _, p = read_varint(frames, p)
                _, p = read_varint(frames, p)
                cnt, p = read_varint(frames, p)
                _, p = read_varint(frames, p)
                for _ in range(cnt):
                    _, p = read_varint(frames, p)
                    _, p = read_varint(frames, p)
                if ft == 0x03:
                    for _ in range(3):
                        _, p = read_varint(frames, p)
            elif ft == 0x06:
                off, p = read_varint(frames, p + 1)
                ln, p = read_varint(frames, p)
                out.append((off, frames[p : p + ln]))
                p += ln
            elif ft in (0x1C, 0x1D):
                break
            else:
                break
    except IndexError:
        pass
    return out


def build_initial(*, version: int, dcid: bytes, scid: bytes, pn: int, frames: bytes, keys: Keys,
                  token: bytes = b"", pad_to: int = 0) -> bytes:
    """Build a protected Initial packet. pad_to pads the payload so the packet reaches that size."""
    pn_len = 2
    first = 0xC0 | (_TYPE_BITS[version]["initial"] << 4) | (pn_len - 1)
    head = (bytes([first]) + struct.pack("!I", version) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
            + varint(len(token)) + token)
    overhead = len(head) + 2 + pn_len + 16
    if pad_to and overhead + len(frames) < pad_to:
        frames = frames + bytes(pad_to - overhead - len(frames))
    length = pn_len + len(frames) + 16
    header = head + struct.pack("!H", 0x4000 | length) + pn.to_bytes(pn_len, "big")
    nonce = (int.from_bytes(keys.iv, "big") ^ pn).to_bytes(12, "big")
    ct = AESGCM(keys.key).encrypt(nonce, frames, header)
    pn_off = len(header) - pn_len
    sample = ct[4 - pn_len : 4 - pn_len + 16]
    mask = _hp_mask(keys.hp, sample)
    out = bytearray(header + ct)
    out[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        out[pn_off + i] ^= mask[1 + i]
    return bytes(out)


def build_long_opaque(*, version: int, ptype: str, dcid: bytes, scid: bytes, body: bytes) -> bytes:
    """A Handshake or 0-RTT packet whose protected body is opaque bytes (keys are never on the wire)."""
    first = 0xC0 | (_TYPE_BITS[version][ptype] << 4) | (body[0] & 0x0F if body else 1)
    return (bytes([first]) + struct.pack("!I", version) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
            + struct.pack("!H", 0x4000 | len(body)) + body)


def build_short(dcid: bytes, body: bytes) -> bytes:
    """1-RTT short header packet with an opaque protected body."""
    first = 0x40 | (body[0] & 0x1F if body else 1)
    return bytes([first]) + dcid + body[1:] if body else bytes([first]) + dcid


def crypto_frame(offset: int, data: bytes) -> bytes:
    return b"\x06" + varint(offset) + varint(len(data)) + data


def ack_frame(largest: int) -> bytes:
    return b"\x02" + varint(largest) + varint(0) + varint(0) + varint(0)
