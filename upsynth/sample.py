"""A small deterministic N3/N6 capture for tests and demos, built without a profile.

It has the traffic a phone makes in a minute: DNS lookups, web pages over TLS 1.3, a QUIC video
stream, messaging over TLS, an RTP-like call, NTP, plain HTTP. Not a substitute for a real capture
(examples/README.md says how to make one with Open5GS + UERANSIM), but every packet is valid.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import numpy as np

from .schemas import UEProfile
from .synth import Encap
from .synth import packets as P
from .synth.behavior import UE, FlowSpec, server_ip
from .synth.templates import TEMPLATES, Ctx, dns_lookup
from .tls import CHROME_JA4_R, CHROME_QUIC_JA4_R

SAFARI_JA4_R = ("t13d2012h2_000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,"
                "c030,cca8,cca9_0005,000a,000b,000d,0017,001b,002b,002d,0033,ff01_"
                "0403,0804,0401,0503,0203,0805,0501,0806,0601,0201")
OKHTTP_JA4_R = ("t13d1713h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_"
                "0005,000a,000b,000d,0015,0017,0023,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0501,0806,0601,0201")

# (app, category, template, port, domain, ja4_r, alpn, n_flows, shape kind)
PLAN = [
    ("google_search", "search", "web_browsing", 443, "www.google.com", CHROME_JA4_R, ["h2", "http/1.1"], 6, "web"),
    ("wikipedia", "web", "web_browsing", 443, "en.wikipedia.org", CHROME_JA4_R, ["h2", "http/1.1"], 6, "web"),
    ("bbc", "news", "web_browsing", 443, "www.bbc.co.uk", SAFARI_JA4_R, ["h2", "http/1.1"], 5, "web"),
    ("youtube", "video", "quic", 443, "rr3---sn-a5mekn6r.googlevideo.com", CHROME_QUIC_JA4_R, ["h3"], 6, "video"),
    ("youtube", "video", "tls_tcp", 443, "i.ytimg.com", CHROME_JA4_R, ["h2", "http/1.1"], 4, "web"),
    ("wechat", "messaging", "tls_tcp", 443, "szextshort.weixin.qq.com", OKHTTP_JA4_R, [], 6, "chat"),
    ("whatsapp", "messaging", "tls_tcp", 443, "g.whatsapp.net", OKHTTP_JA4_R, ["h2", "http/1.1"], 5, "chat"),
    ("spotify", "music", "tls_tcp", 443, "audio-ak-spotify-com.akamaized.net", OKHTTP_JA4_R, ["h2", "http/1.1"], 5, "video"),
    ("zoom", "conferencing", "udp", 8801, None, None, [], 5, "rtp"),
    ("ntp", "ntp", "udp", 123, None, None, [], 5, "ntp"),
    ("web_http", "web", "tcp", 80, "connectivitycheck.gstatic.com", None, [], 5, "http"),
]


def _shape(kind: str, rng: np.random.Generator) -> list[tuple[int, float]]:
    def g(lo, hi):
        return float(rng.uniform(lo, hi))

    if kind == "web":
        s = [(60, 0.0), (-60, g(15, 40)), (52, 0.2), (int(g(560, 640)), 0.3), (-1400, g(15, 40))]
        s += [(-1400, g(0.01, 0.3)) for _ in range(3)] + [(-int(g(300, 900)), 0.1), (52, 0.3), (110, 0.2), (int(g(300, 600)), 0.2)]
        for _ in range(int(g(2, 6))):
            s += [(-1400, g(10, 60))] + [(-1400, g(0.01, 0.5)) for _ in range(int(g(3, 20)))] + [(52, 0.2)]
            s += [(int(g(90, 500)), g(50, 800))]
        return s
    if kind == "video":
        s = [(1278, 0.0), (-1278, g(15, 40)), (-1278, 0.2), (-int(g(400, 1000)), 0.2), (90, 0.5), (int(g(200, 500)), 1.0)]
        for _ in range(int(g(10, 25))):
            s += [(-1278, g(5, 2000))] + [(-1278, g(0.01, 0.2)) for _ in range(int(g(20, 80)))] + [(60, 0.5)]
        return s
    if kind == "chat":
        s = [(60, 0.0), (-60, g(15, 40)), (52, 0.2), (int(g(300, 520)), 0.2), (-int(g(1300, 1400)), g(20, 50)),
             (-int(g(200, 1300)), 0.2), (52, 0.2), (int(g(100, 200)), 0.3)]
        for _ in range(int(g(5, 30))):
            s += [(int(g(80, 400)), g(500, 8000)), (-52, g(20, 50)), (-int(g(80, 600)), g(100, 3000)), (52, 0.2)]
        return s
    if kind == "rtp":
        s = []
        for i in range(int(g(300, 900))):
            s.append((int(g(120, 260)) * (1 if i % 2 == 0 else -1), 0.0 if i == 0 else g(8, 12)))
        return s
    if kind == "ntp":
        return [(76, 0.0), (-76, g(10, 60))]
    if kind == "http":
        return [(60, 0.0), (-60, g(15, 40)), (52, 0.2), (int(g(180, 260)), 0.3), (-52, g(15, 40)),
                (-int(g(300, 600)), 1.0), (52, 0.2)]
    raise ValueError(kind)


def make_sample(path: str | Path, *, iface: str = "n3", seed: int = 7, ues: int = 3, start: float = 1767254400.0) -> dict:
    rng = np.random.default_rng(seed)
    resolver = ipaddress.IPv4Address("8.8.8.8").packed
    mtu = 1400 if iface == "n3" else 1500
    ue_list = [UE(i, f"ue{i + 1}", (ipaddress.IPv4Address("10.45.0.2") + i).packed, b"", 0x100 + i, 0x200 + i,
                  UEProfile.model_construct()) for i in range(ues)]
    frames: list[tuple[float, bool, bytes, int, UE]] = []
    flows = 0
    port = 40000
    for app, cat, tpl, sport, domain, ja4_r, alpn, n, kind in PLAN:
        for _ in range(n):
            ue = ue_list[int(rng.integers(ues))]
            t = start + float(rng.uniform(0, 60))
            srv = server_ip(domain or f"{app}:{int(rng.integers(3))}", 4)
            port += 1
            ctx = Ctx(rng, ue.ip4, srv, port, mtu)
            spec = FlowSpec(0, ue.index, app, cat, {"web_browsing": "tls_tcp"}.get(tpl, tpl), tpl, t, sport, domain,
                            ja4_r, list(alpn), 9 if cat != "conferencing" else 1, 4, _shape(kind, rng))
            pk = []
            if domain:
                d, _ = dns_lookup(ctx, resolver, domain, srv, t - 0.06)
                pk += d
            pk += TEMPLATES[tpl](spec, ctx)
            frames += [(ts, up, l3, spec.qfi, ue) for ts, up, l3 in pk]
            flows += 1
    frames.sort(key=lambda x: x[0])
    enc = Encap(iface)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        w = P.PcapWriter(f)
        for ts, up, l3, qfi, ue in frames:
            w.write(ts, enc.frame(up, l3, ue.teid_ul if up else ue.teid_dl, qfi))
    return {"output": str(path), "iface": iface, "flows": flows, "frames": len(frames)}
