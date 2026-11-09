"""synth: profile.json -> out.pcap + labels.csv"""

from __future__ import annotations

import csv
import heapq
import ipaddress
from collections import Counter
from pathlib import Path

import numpy as np

from ..label import load_kb
from ..schemas import Profile
from ..tls import ja4_from_raw
from . import packets as P
from .behavior import Behaviour, FlowSpec, server_ip
from .check import find_tshark, tshark_check
from .protocols import load_registry
from .templates import TEMPLATES, Ctx, dns_lookup

DEFAULT_START = 1767254400.0  # 2026-01-01 08:00:00 UTC
GNB_IP = ipaddress.IPv4Address("10.10.0.11").packed
UPF_N3_IP = ipaddress.IPv4Address("10.10.0.7").packed
MAC_GNB, MAC_UPF_N3 = bytes.fromhex("020000000a0b"), bytes.fromhex("020000000a07")
MAC_UPF_N6, MAC_ROUTER = bytes.fromhex("020000000b07"), bytes.fromhex("020000000b01")

LABEL_COLUMNS = ["flow_id", "app", "category", "transport", "template", "ue", "start", "end", "iface", "ip_version",
                 "proto", "ue_ip", "ue_port", "server_ip", "server_port", "domain", "alpn", "ja4", "qfi", "teid_ul",
                 "teid_dl", "packets", "bytes", "service", "action", "action_id"]


def load_profile(path: str | Path) -> Profile:
    return Profile.model_validate_json(Path(path).read_text(encoding="utf-8"))


class Encap:
    def __init__(self, iface: str):
        self.iface = iface
        self.ident = {True: 1, False: 1}

    def frame(self, up: bool, l3: bytes, teid: int, qfi: int) -> bytes:
        if self.iface == "n6":
            return P.ethernet(MAC_UPF_N6, MAC_ROUTER, l3) if up else P.ethernet(MAC_ROUTER, MAC_UPF_N6, l3)
        src, dst = (GNB_IP, UPF_N3_IP) if up else (UPF_N3_IP, GNB_IP)
        g = P.gtpu(teid, l3, qfi=qfi, uplink=up)
        self.ident[up] += 1
        outer = P.ip_packet(src, dst, 17, P.udp(src, dst, 2152, 2152, g, csum=False), ident=self.ident[up])
        return P.ethernet(MAC_GNB, MAC_UPF_N3, outer) if up else P.ethernet(MAC_UPF_N3, MAC_GNB, outer)


def run(profile: str | Path, out: str | Path, labels: str | Path | None = None, *, ues: int = 10,
        duration: float = 300.0, iface: str = "n3", seed: int = 0, start: float | None = None,
        apps: list[str] | None = None, kb_path: str | Path | None = None, mtu: int | None = None,
        dns_server: str = "8.8.8.8", dns_server6: str = "2001:4860:4860::8888", max_flow_packets: int = 5000,
        check: bool = True, mode: str = "flows", script: str | Path | None = None, rtt_ms: float = 0.0,
        bw_mbps: float | None = None, cdn_region: str | None = None) -> dict:
    """mode "flows": sessions of flows (app mix and transitions); "actions": flows opened by actions, walked from
    the profile's action chain or played from a script (JSON, schemas.Script), which implies "actions"."""
    if iface not in ("n3", "n6"):
        raise ValueError("iface must be n3 or n6")
    prof = load_profile(profile)
    if not prof.apps:
        raise ValueError("profile has no apps")
    if apps:
        missing = [a for a in apps if a not in {x.app for x in prof.apps}]
        if missing:
            raise ValueError(f"apps not in profile: {', '.join(missing)}")
    rng = np.random.default_rng(seed)
    kb_templates = {a.name: a.template for a in load_kb(kb_path).apps if a.template}
    mtu = mtu or (1400 if iface == "n3" else 1500)
    registry = load_registry(find_tshark())
    beh = Behaviour(prof, rng, kb_templates=kb_templates, mtu=mtu, max_flow_packets=max_flow_packets,
                    registry=registry, rtt_ms=rtt_ms, bw_mbps=bw_mbps, cdn_region=cdn_region)
    ue_list = beh.make_ues(ues)
    t0 = DEFAULT_START if start is None else start
    action_rows: list[dict] = []
    if script or mode == "actions":
        from ..actions import check_script
        from ..schemas import Script

        if prof.action_model is None:
            raise ValueError("profile has no action model; build it with: upsynth profile ... --actions <log>|bursts")
        sc = None
        if script:
            sc = check_script(prof.action_model, Script.model_validate_json(Path(script).read_text(encoding="utf-8")))
        specs, action_rows = beh.schedule_actions(ue_list, t0, duration, sc)
        mode = "actions"
    elif mode == "flows":
        specs = beh.schedule(ue_list, t0, duration, set(apps) if apps else None)
    else:
        raise ValueError("mode must be flows or actions")
    resolver4 = ipaddress.IPv4Address(dns_server).packed
    resolver6 = ipaddress.IPv6Address(dns_server6).packed
    enc = Encap(iface)
    out = Path(out)
    labels = Path(labels) if labels else out.with_suffix(".labels.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    labels.parent.mkdir(parents=True, exist_ok=True)
    next_port = {u.index: int(rng.integers(33000, 50000)) for u in ue_list}
    rows: list[dict] = []
    by_app: Counter = Counter()
    by_template: Counter = Counter()
    label_id = 0

    def materialize(spec: FlowSpec):
        nonlocal label_id
        ue = ue_list[spec.ue]
        v6 = spec.ip_version == 6
        ue_ip = ue.ip6 if v6 else ue.ip4
        srv = server_ip(spec.domain or f"{spec.app}:{spec.flow_id % 5}", 6 if v6 else 4)
        port = next_port[ue.index]
        next_port[ue.index] = port + 1 if port < 60999 else 33000
        ctx = Ctx(rng, ue_ip, srv, port, mtu)
        out_pkts = []
        if spec.dns_first and spec.domain:
            resolver = resolver6 if v6 else resolver4
            dpk, _ = dns_lookup(ctx, resolver, spec.domain, srv, spec.start - ctx.ms(40, 120))
            label_id += 1
            rows.append(_row(label_id, "dns", "dns", "dns", "dns", ue, dpk, iface, v6, 17, ue_ip, resolver, 53,
                             spec.domain, None, None, spec.qfi, _sport(dpk[0][2]), spec.extras.get("action"),
                             spec.extras.get("action_id"), spec.extras.get("service")))
            out_pkts += [(t, up, l3, spec.qfi) for t, up, l3 in dpk]
        fn = TEMPLATES.get(spec.template) or TEMPLATES[spec.transport]
        pk = fn(spec, ctx)
        label_id += 1
        proto = 6 if spec.transport in ("tls_tcp", "tcp") else 17
        ja4 = ja4_from_raw(spec.ja4_r) if spec.ja4_r and spec.transport in ("tls_tcp", "quic") else None
        rows.append(_row(label_id, spec.app, spec.category, spec.transport, spec.template, ue, pk, iface, v6, proto,
                         ue_ip, srv, spec.server_port, spec.domain, ",".join(spec.alpn) or None, ja4, spec.qfi, port,
                         spec.extras.get("action"), spec.extras.get("action_id"), spec.extras.get("service")))
        by_app[spec.app] += 1
        by_template[spec.template] += 1
        out_pkts += [(t, up, l3, spec.qfi) for t, up, l3 in pk]
        out_pkts.sort(key=lambda x: x[0])
        return ue, out_pkts

    heap: list = []
    seq = 0
    i = 0
    frames = 0
    with open(out, "wb") as f:
        w = P.PcapWriter(f)
        def horizon_now() -> float:
            # flows start materializing 1 s ahead (their DNS lookup comes first); with nothing pending, take the next one
            if heap:
                return heap[0][0] + 1.0
            return specs[i].start if i < len(specs) else float("inf")

        while i < len(specs) or heap:
            horizon = horizon_now()
            while i < len(specs) and specs[i].start <= horizon:
                ue, pk = materialize(specs[i])
                i += 1
                if pk:
                    it = iter(pk)
                    first = next(it)
                    heapq.heappush(heap, (first[0], seq, first, it, ue))
                    seq += 1
                horizon = horizon_now()
            if not heap:
                continue
            ts, _, (t, up, l3, qfi), it, ue = heapq.heappop(heap)
            w.write(t, enc.frame(up, l3, ue.teid_ul if up else ue.teid_dl, qfi))
            frames += 1
            nxt = next(it, None)
            if nxt is not None:
                heapq.heappush(heap, (nxt[0], seq, nxt, it, ue))
                seq += 1
    rows.sort(key=lambda r: r["start"])
    with open(labels, "w", newline="", encoding="utf-8") as f:
        cw = csv.DictWriter(f, fieldnames=LABEL_COLUMNS)
        cw.writeheader()
        cw.writerows(rows)
    actions_path = None
    if action_rows:
        actions_path = out.with_suffix(".actions.csv")
        with open(actions_path, "w", newline="", encoding="utf-8") as f:
            cw = csv.DictWriter(f, fieldnames=["action_id", "ue", "ue_ip", "action", "service", "start", "end"])
            cw.writeheader()
            cw.writerows({**a, "start": f"{a['start']:.6f}", "end": f"{a['end']:.6f}"} for a in action_rows)
    result = {
        "profile": str(profile),
        "output": str(out),
        "labels": str(labels),
        "iface": iface,
        "ues": ues,
        "duration": duration,
        "seed": seed,
        "mode": mode,
        "flows": len(specs),
        "actions": len(action_rows) if action_rows else None,
        "actions_csv": str(actions_path) if actions_path else None,
        "script_dwell_outside_profile": beh.dwell_outside if script else None,
        "dns_lookups": sum(1 for r in rows if r["app"] == "dns"),
        "frames": frames,
        "by_app": dict(by_app.most_common()),
        "by_template": dict(by_template.most_common()),
        # opaque flows moved off ports where a Wireshark dissector expects another protocol
        "ports_remapped": dict(beh.remapped.most_common()),
    }
    if check:
        result["check"] = tshark_check(out)
    return result


def _sport(l3: bytes) -> int:
    ihl = 20 if l3[0] >> 4 == 4 else 40
    return int.from_bytes(l3[ihl : ihl + 2], "big")


def _row(fid, app, category, transport, template, ue, pk, iface, v6, proto, ue_ip, srv, sport, domain, alpn, ja4,
         qfi, ue_port, action=None, action_id=None, service=None) -> dict:
    return {
        "flow_id": fid,
        "app": app,
        "category": category,
        "transport": transport,
        "template": template,
        "ue": ue.name,
        "start": f"{min(p[0] for p in pk):.6f}" if pk else "",
        "end": f"{max(p[0] for p in pk):.6f}" if pk else "",
        "iface": iface,
        "ip_version": 6 if v6 else 4,
        "proto": proto,
        "ue_ip": str(ipaddress.ip_address(ue_ip)),
        "ue_port": ue_port,
        "server_ip": str(ipaddress.ip_address(srv)),
        "server_port": sport,
        "domain": domain or "",
        "alpn": alpn or "",
        "ja4": ja4 or "",
        "qfi": qfi if iface == "n3" else "",
        "teid_ul": f"0x{ue.teid_ul:08x}" if iface == "n3" else "",
        "teid_dl": f"0x{ue.teid_dl:08x}" if iface == "n3" else "",
        "packets": len(pk),
        "bytes": sum(len(p[2]) for p in pk),
        "service": service or "other",
        "action": action or "",
        "action_id": action_id or "",
    }
