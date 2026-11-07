"""Offline IP to ASN lookup, no network and no C extension.

Accepted files (optionally .gz):
- iptoasn.com ip2asn-v4.tsv / ip2asn-combined.tsv: "range_start<TAB>range_end<TAB>asn<TAB>..."
- pyasn ipasn .dat: "prefix/len<TAB>asn" (comment lines start with ';')
- CSV "prefix,asn"
"""

from __future__ import annotations

import bisect
import gzip
import ipaddress
from pathlib import Path


class AsnDB:
    def __init__(self) -> None:
        self._starts: dict[int, list[int]] = {4: [], 6: []}
        self._rows: dict[int, list[tuple[int, int, int]]] = {4: [], 6: []}

    @classmethod
    def load(cls, path: str | Path) -> "AsnDB":
        db = cls()
        p = Path(path)
        opener = gzip.open if p.suffix == ".gz" else open
        rows: dict[int, list[tuple[int, int, int]]] = {4: [], 6: []}
        with opener(p, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line[0] in ";#":
                    continue
                parts = line.replace(",", "\t").split("\t")
                try:
                    if "/" in parts[0]:
                        net = ipaddress.ip_network(parts[0], strict=False)
                        lo, hi, ver = int(net.network_address), int(net.broadcast_address), net.version
                        asn = int(parts[1])
                    else:
                        a, b = ipaddress.ip_address(parts[0]), ipaddress.ip_address(parts[1])
                        lo, hi, ver = int(a), int(b), a.version
                        asn = int(parts[2])
                except (ValueError, IndexError):
                    continue
                if asn > 0:
                    rows[ver].append((lo, hi, asn))
        for ver, rs in rows.items():
            rs.sort()
            db._rows[ver] = rs
            db._starts[ver] = [r[0] for r in rs]
        return db

    def __len__(self) -> int:
        return len(self._rows[4]) + len(self._rows[6])

    def lookup(self, packed: bytes) -> int | None:
        ver = 4 if len(packed) == 4 else 6
        n = int.from_bytes(packed, "big")
        starts = self._starts[ver]
        i = bisect.bisect_right(starts, n) - 1
        # ranges may nest (pyasn prefixes); walk back a little for the most specific covering range
        best = None
        for j in range(i, max(i - 8, -1), -1):
            lo, hi, asn = self._rows[ver][j]
            if lo <= n <= hi and (best is None or hi - lo < best[0]):
                best = (hi - lo, asn)
        return best[1] if best else None
