"""profile: labeled.parquet -> profile.json

Everything is a histogram, a categorical share, a cluster center or a chain; no single flow is
written. Apps seen in fewer than --min-flows flows or by fewer than --min-ues UEs are folded into
"other" so a rare app cannot point back at one user. UEs are renumbered (ue1, ue2...), the HMAC
tokens never appear. Server names are kept only when the knowledge base matched them (public apps).
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

from . import __version__, pacing
from .schemas import (SEQ_LEN, AppProfile, Categorical, Cluster, Hist, MarkovChain, Profile, ProfileMeta,
                      UEProfile)

OTHER = "other"

DURATION_EDGES = [0.0] + list(np.logspace(-3, 5, 33))
COUNT_EDGES = sorted(set(int(round(x)) for x in np.logspace(0, 7, 57))) + [10**7 + 1]
BYTES_EDGES = list(np.logspace(1, 11, 61))
# fine where exact sizes repeat (ACKs, handshakes, full-MTU packets), coarse in between
LEN_EDGES = list(range(0, 128, 4)) + list(range(128, 1200, 32)) + list(range(1200, 1524, 4)) + [1600, 9000, 65536]
IAT_EDGES = [0.0] + list(np.logspace(-2, 7, 37))  # ms
GAP_EDGES = [0.0] + list(np.logspace(-3, 4, 29))  # s
CONC_EDGES = list(range(1, 33)) + [64, 1024]
RUN_EDGES = [0.5] + list(np.logspace(0, 3, 19))  # s
CHAIN_EDGES = [0, 100, 200, 400, 600, 800, 1000, 1200, 1400, 65536]


def hist(values, edges, scale="linear") -> Hist:
    v = np.asarray(values, dtype=float)
    v = v[np.isfinite(v)]
    e = np.asarray(edges, dtype=float)
    if v.size == 0:
        return Hist(edges=[float(e[0]), float(e[1])], probs=[1.0], scale=scale)
    v = np.clip(v, e[0], np.nextafter(e[-1], -np.inf))
    counts, _ = np.histogram(v, bins=e)
    nz = np.nonzero(counts)[0]
    lo, hi = nz[0], nz[-1] + 1
    probs = counts[lo:hi] / counts.sum()
    return Hist(edges=[round(float(x), 6) for x in e[lo : hi + 1]], probs=[round(float(p), 6) for p in probs], scale=scale)


def categorical(values) -> Categorical:
    c = Counter(values)
    total = sum(c.values())
    if not total:
        return Categorical(values=[], probs=[])
    items = c.most_common()
    return Categorical(values=[str(k) for k, _ in items], probs=[round(n / total, 6) for _, n in items])


def kmeans(x: np.ndarray, k: int, seed: int = 0, iters: int = 50) -> tuple[np.ndarray, np.ndarray]:
    """Plain k-means++ (numpy only). Returns (centers, labels)."""
    rng = np.random.default_rng(seed)
    n = len(x)
    k = max(1, min(k, n))
    centers = [x[rng.integers(n)]]
    for _ in range(1, k):
        d = np.min(((x[:, None, :] - np.asarray(centers)[None]) ** 2).sum(-1), axis=1)
        if d.sum() == 0:
            break
        centers.append(x[rng.choice(n, p=d / d.sum())])
    c = np.asarray(centers, dtype=float)
    labels = np.zeros(n, dtype=int)
    for _ in range(iters):
        d = ((x[:, None, :] - c[None]) ** 2).sum(-1)
        new = d.argmin(1)
        if np.array_equal(new, labels) and _ > 0:
            break
        labels = new
        for j in range(len(c)):
            m = labels == j
            if m.any():
                c[j] = x[m].mean(0)
    return c, labels


MIN_CLUSTER = 3  # smaller clusters join the nearest larger one, so no cluster stands for one flow
BULK_BYTES = 1_000_000  # downlink bytes from which a flow counts as bulk (a stream, a video segment run)


def seq_clusters(seqs: list[list[int]], seed: int) -> list[Cluster]:
    if not seqs:
        return []
    x = np.zeros((len(seqs), SEQ_LEN))
    for i, s in enumerate(seqs):
        x[i, : len(s)] = s[:SEQ_LEN]
    k = max(1, min(8, len(seqs) // 5))
    c, labels = kmeans(x, k, seed)
    counts = np.bincount(labels, minlength=len(c))
    big = np.nonzero(counts >= MIN_CLUSTER)[0]
    if len(big) == 0:
        labels[:] = 0
        c = x.mean(0, keepdims=True)
    else:
        for j in np.nonzero((counts > 0) & (counts < MIN_CLUSTER))[0]:
            members = labels == j
            d = ((x[members][:, None, :] - c[big][None]) ** 2).sum(-1)
            labels[np.nonzero(members)[0]] = big[d.argmin(1)]
        for j in big:
            c[j] = x[labels == j].mean(0)
    n_states = 2 * (len(CHAIN_EDGES) - 1)
    out = []
    w = np.bincount(labels, minlength=len(c)) / len(seqs)
    for j in np.argsort(-w):
        if w[j] == 0:
            continue
        members = [seqs[i] for i in np.nonzero(labels == j)[0]]
        positions = []
        for p in range(SEQ_LEN):
            cnt = np.zeros(n_states + 1)
            for s in members:
                cnt[_state(s[p]) if p < len(s) else n_states] += 1
            positions.append([(int(st), round(float(v / cnt.sum()), 4)) for st, v in enumerate(cnt) if v])
        out.append(Cluster(weight=round(float(w[j]), 6), center=[float(round(v)) for v in c[j]], positions=positions))
    return out


def _state(v: int) -> int:
    d = 0 if v > 0 else 1
    b = int(np.searchsorted(CHAIN_EDGES, abs(v), side="right") - 1)
    return d * (len(CHAIN_EDGES) - 1) + min(b, len(CHAIN_EDGES) - 2)


def markov(seqs: list[list[int]]) -> MarkovChain | None:
    nb = len(CHAIN_EDGES) - 1
    ns = 2 * nb
    trans = np.zeros((ns, ns))
    start = np.zeros(ns)
    for s in seqs:
        if not s:
            continue
        st = [_state(v) for v in s]
        start[st[0]] += 1
        for a, b in zip(st, st[1:]):
            trans[a, b] += 1
    if trans.sum() == 0:
        return None
    seen = (trans.sum(1) + trans.sum(0)) > 0
    for i in range(ns):
        if trans[i].sum() == 0:
            trans[i] = seen.astype(float)
    trans = trans / trans.sum(1, keepdims=True)
    names = [f"{d}:{CHAIN_EDGES[b]}-{CHAIN_EDGES[b + 1]}" for d in "ud" for b in range(nb)]
    return MarkovChain(states=names, edges=[float(e) for e in CHAIN_EDGES],
                       start=[round(float(p), 6) for p in start / start.sum()],
                       trans=[[round(float(p), 6) for p in row] for row in trans])


def transport(r: dict) -> str:
    if r["proto"] == 17 and r["server_port"] == 53:
        return "dns"
    if r["proto"] == 17:
        return "quic" if r.get("quic_version") else "udp"
    if r["server_port"] == 53:
        return "dns"
    return "tls_tcp" if (r.get("ja4") or r.get("sni")) else "tcp"


def concurrency(rows: list[dict]) -> dict[int, int]:
    """For each row index: flows of the same UE and app open at its start (itself included)."""
    out = {}
    groups = defaultdict(list)
    for i, r in enumerate(rows):
        groups[(r["ue"], r["_app"])].append(i)
    for idx in groups.values():
        starts = np.array([rows[i]["start"] for i in idx])
        ends = np.sort(np.array([rows[i]["end"] for i in idx]))
        s_sorted = np.sort(starts)
        for i, t in zip(idx, starts):
            out[i] = int(np.searchsorted(s_sorted, t, side="right") - np.searchsorted(ends, t, side="left"))
    return out


def app_profile(app: str, rs: list[dict], conc: list[int], n_total: int, seed: int) -> AppProfile:
    """Distributions of one app's flows (rs); conc: concurrency per flow, n_total: flows of all apps."""
    cats = Counter(r["category"] for r in rs)
    up_lens = [v for r in rs for v in (r["seq_len"] or []) if v > 0]
    down_lens = [-v for r in rs for v in (r["seq_len"] or []) if v < 0]
    iats = [v for r in rs for v in (r["seq_iat"] or [])[1:]]
    seqs = [list(r["seq_len"] or []) for r in rs]
    named = [r.get("sni") or r.get("http_host") or r.get("dns_name") for r in rs
             if r["label_source"] in ("sni", "http_host", "dns")]
    on_runs, off_runs = [], []
    for r in rs:
        rd = r.get("rate_down") or []
        if r["duration"] >= 3 and len(rd) >= 3:
            a, b = pacing.runs(pacing.busy(rd))
            on_runs += a
            off_runs += b
    tails = {1: [], -1: []}
    for r in rs:
        seq = r["seq_len"] or []
        for sign, pk, by in ((1, r["pkts_up"], r["bytes_up"]), (-1, r["pkts_down"], r["bytes_down"])):
            head = [abs(v) for v in seq if (v > 0) == (sign > 0)]
            if len(seq) >= SEQ_LEN and pk > len(head):
                tails[sign].append((by - sum(head)) / (pk - len(head)))
    return AppProfile(
        app=app,
        category=cats.most_common(1)[0][0] if app != OTHER else OTHER,
        flow_share=round(len(rs) / n_total, 6) if n_total else 0.0,
        flows=len(rs),
        ues=len({r["ue"] for r in rs}),
        transport=categorical(r["_transport"] for r in rs),
        endpoints=categorical(f"{r['_transport']}/{r['server_port']}" for r in rs),
        alpn=categorical(r["alpn"] for r in rs if r.get("alpn")),
        domains=categorical(n for n in named if n) if app != OTHER else Categorical(values=[], probs=[]),
        ja4_r=categorical(r["ja4_r"] for r in rs if r.get("ja4_r")),
        qfi=categorical(r["qfi"] for r in rs if r.get("qfi") is not None),
        duration=hist([r["duration"] for r in rs], DURATION_EDGES, "log"),
        pkts=hist([r["pkts_up"] + r["pkts_down"] for r in rs], COUNT_EDGES, "log"),
        tail_len_up=hist(tails[1], LEN_EDGES) if len(tails[1]) >= MIN_CLUSTER else None,
        tail_len_down=hist(tails[-1], LEN_EDGES) if len(tails[-1]) >= MIN_CLUSTER else None,
        pkts_up=hist([r["pkts_up"] for r in rs], COUNT_EDGES, "log"),
        pkts_down=hist([r["pkts_down"] for r in rs], COUNT_EDGES, "log"),
        bytes_up=hist([max(r["bytes_up"], 10) for r in rs], BYTES_EDGES, "log"),
        bytes_down=hist([max(r["bytes_down"], 10) for r in rs], BYTES_EDGES, "log"),
        len_up=hist(up_lens, LEN_EDGES),
        len_down=hist(down_lens, LEN_EDGES),
        iat=hist(iats, IAT_EDGES, "log"),
        on_s=hist(on_runs, RUN_EDGES, "log") if len(on_runs) >= MIN_CLUSTER else None,
        off_s=hist(off_runs, RUN_EDGES, "log") if len(off_runs) >= MIN_CLUSTER else None,
        seq_clusters=seq_clusters(seqs, seed),
        chain=markov(seqs),
        concurrency=hist(conc, CONC_EDGES),
    )


def build(rows: list[dict], *, min_flows: int = 5, min_ues: int = 1, session_gap: float = 300.0, seed: int = 0,
          actions: str | Path | None = None, burst_gap: float = 1.5, action_types: int = 6) -> Profile:
    """actions: path of an action log, or "bursts" to find actions in the traffic; None for no action model."""
    dns_rows = [r for r in rows if transport(r) == "dns"]
    rows = [r for r in rows if transport(r) != "dns"]
    app_flows = Counter(r["app"] for r in rows)
    app_ues = defaultdict(set)
    for r in rows:
        app_ues[r["app"]].add(r["ue"])
    keep = {a for a, n in app_flows.items() if n >= min_flows and len(app_ues[a]) >= min_ues}
    for r in rows:
        r["_app"] = r["app"] if r["app"] in keep else OTHER
        r["_transport"] = transport(r)
    conc = concurrency(rows)
    by_app = defaultdict(list)
    for i, r in enumerate(rows):
        by_app[r["_app"]].append(i)
    n_total = len(rows)
    apps = []
    for app, idx in sorted(by_app.items(), key=lambda kv: -len(kv[1])):
        apps.append(app_profile(app, [rows[i] for i in idx], [conc[i] for i in idx], n_total, seed))
    # ---------------------------------------------------------------- UEs
    by_ue = defaultdict(list)
    for r in rows:
        by_ue[r["ue"]].append(r)
    span = (max(r["end"] for r in rows) - min(r["start"] for r in rows)) if rows else 0.0
    ues = []
    transitions = defaultdict(Counter)
    order = sorted(by_ue, key=lambda u: min(r["start"] for r in by_ue[u]))
    for n, u in enumerate(order, 1):
        rs = sorted(by_ue[u], key=lambda r: r["start"])
        starts = np.array([r["start"] for r in rs])
        gaps = np.diff(starts)
        inside = gaps[gaps <= session_gap]
        sessions = np.split(starts, np.nonzero(gaps > session_gap)[0] + 1)
        sess_span = sum(s[-1] - s[0] for s in sessions)
        hours = [int((t % 86400) // 3600) for t in starts]
        hc = np.bincount(hours, minlength=24) / len(hours)
        for a, b in zip(rs, rs[1:]):
            if b["start"] - a["start"] <= session_gap:
                transitions[a["_app"]][b["_app"]] += 1
        ues.append(UEProfile(
            ue=f"ue{n}",
            active_hours=[round(float(x), 6) for x in hc],
            app_mix=categorical(r["_app"] for r in rs),
            flow_rate=round(float(len(inside) / sess_span), 6) if sess_span > 0 else 0.0,
            inter_flow=hist(inside, GAP_EDGES, "log"),
            session_flows=hist([len(s) for s in sessions], COUNT_EDGES, "log"),
            session_gap=session_gap,
            sessions_per_hour=round(len(sessions) / max(span / 3600.0, 1.0 / 60), 6),
        ))
    meta = ProfileMeta(
        version=__version__,
        flows=len(rows),
        ues=len(by_ue),
        span_seconds=round(float(span), 3),
        iface=categorical(r["iface"] for r in rows),
        ip_version=categorical(r["ip_version"] for r in rows),
        min_flows_per_app=min_flows,
        min_ues_per_app=min_ues,
        dns_ratio=round(min(len(dns_rows) / len(rows), 1.0), 6) if rows else 0.0,
    )
    model = None
    if actions:
        from . import actions as act

        inst = act.find_instances(rows, log=None if str(actions) == "bursts" else actions, gap=burst_gap,
                                  k=action_types, seed=seed)
        # flows of one app look different per service (a live stream is not a VOD fetch): one sub-profile per
        # (app, service), "bilibili@live", used by the action slots; flow_share 0 keeps flow mode unchanged
        # bulk flows (the stream, the video segments) get their own sub-profile, or their durations would be drawn
        # from the many small API and image flows of the same service
        sub = defaultdict(list)
        for i, r in enumerate(rows):
            if r.get("_svc") and r["_app"] != OTHER:
                sub[(r["_app"], r["_svc"], r["bytes_down"] >= BULK_BYTES)].append(i)
        services_of = defaultdict(set)
        for app, svc, _ in sub:
            services_of[app].add(svc)
        for (app, svc, bulk), idx in sorted(sub.items()):
            if len(idx) >= MIN_CLUSTER and len(services_of[app]) > 1:
                name = f"{app}@{svc}" + ("+bulk" if bulk else "")
                ap = app_profile(name, [rows[i] for i in idx], [conc[i] for i in idx], n_total, seed)
                ap.flow_share = 0.0
                apps.append(ap)
                for i in idx:
                    rows[i]["_slot_app"] = name
        model = act.build_model(inst, "log" if str(actions) != "bursts" else "bursts")
    return Profile(meta=meta, apps=apps, ues=ues,
                   app_transitions={a: categorical(c.elements()) for a, c in transitions.items()},
                   action_model=model)


def run(labeled: str | Path, out: str | Path, *, min_flows: int = 5, min_ues: int = 1, session_gap: float = 300.0,
        seed: int = 0, actions: str | Path | None = None, burst_gap: float = 1.5, action_types: int = 6) -> dict:
    rows = pq.read_table(labeled).to_pylist()
    prof = build(rows, min_flows=min_flows, min_ues=min_ues, session_gap=session_gap, seed=seed, actions=actions,
                 burst_gap=burst_gap, action_types=action_types)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(prof.model_dump(), indent=1, ensure_ascii=False), encoding="utf-8")
    return {
        "input": str(labeled),
        "output": str(out),
        "flows": prof.meta.flows,
        "ues": prof.meta.ues,
        "apps": [a.app for a in prof.apps],
        "folded_into_other": sorted({r["app"] for r in rows if r.get("_app") == OTHER and r["app"] != OTHER}),
        "dns_ratio": prof.meta.dns_ratio,
        "actions": [a.name for a in prof.action_model.actions] if prof.action_model else None,
    }
