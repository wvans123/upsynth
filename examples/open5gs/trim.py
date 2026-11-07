"""Keep the first K frames of every user flow (inner 5-tuple on N3), so a capture fits in the repository.

Frames are copied unchanged; handshakes, DNS and GTP-U headers stay intact.
Usage: python trim.py in.pcap out.pcap [K]
"""

import struct
import sys
from collections import Counter

import dpkt

from upsynth.pcapio import GTPU_PORT, ReadStats, _gtpu, _ip, _l3_from_link, open_reader


def flow_key(dlt: int, buf: bytes, stats: ReadStats):
    ip = _ip(_l3_from_link(dlt, buf) or b"", stats)
    if ip is None:
        return None
    ver, src, dst, proto, l4, _ = ip
    if proto == 17 and len(l4) >= 8 and GTPU_PORT in struct.unpack_from("!HH", l4, 0):
        g = _gtpu(l4[8:])
        if g is None:
            return None
        ip = _ip(g[3], stats)
        if ip is None:
            return None
        ver, src, dst, proto, l4, _ = ip
    ports = struct.unpack_from("!HH", l4, 0) if proto in (6, 17) and len(l4) >= 4 else (0, 0)
    a, b = (src, ports[0]), (dst, ports[1])
    return (proto,) + ((a, b) if a <= b else (b, a))


def main(src: str, dst: str, k: int = 24) -> None:
    seen: Counter = Counter()
    stats = ReadStats()
    kept = total = 0
    with open(src, "rb") as f, open(dst, "wb") as g:
        r = open_reader(f)
        w = dpkt.pcap.Writer(g, linktype=r.datalink(), snaplen=65535)
        for ts, buf in r:
            total += 1
            key = flow_key(r.datalink(), buf, stats)
            if key is None:
                continue
            seen[key] += 1
            if seen[key] <= k:
                w.writepkt(buf, ts)
                kept += 1
    print(f"{dst}: kept {kept} of {total} frames, {len(seen)} flows")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 24)
