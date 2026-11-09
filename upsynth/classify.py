"""Behaviour classifier: is a UE watching video on demand, live, short videos, or something else?

Unit: a slice = one UE, one app (or one server when the app is unknown), one window (default 30 s,
every 15 s). Features come from the per-second byte series and flow structure and avoid what changes
between regions: no addresses, ASNs, server names, absolute rates or delays.

Labels, best first:
- truth: time intervals with a service (an action log from a lab or phone run, or synth's
  <out>.actions.csv)
- weak: the knowledge-base category of the slice's app (video -> vod, live_streaming -> live,
  short_video -> short_video); apps that mix services (Bilibili) are left out of weak labels

The model is LightGBM (pip install 'upsynth[ml]'). Evaluation holds out whole regions, apps or time
blocks, never random slices, so neighbouring windows of one session cannot leak into the test set.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import math
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

from . import pacing
from .anon import Anonymizer
from .schemas import SERVICE_OF_CATEGORY, SERVICES

# scale-free on purpose: no absolute rate or byte count, no count of idle connections (that depends on the client)
FEATURES = ["idle_frac", "cv", "peak3_share", "acf_max", "on_runs", "on_mean", "off_mean", "longest_on",
            "busy_period", "up_down", "flows_started", "top_share", "top_age", "top_busy", "full_pkt_share",
            "small_pkt_share", "quic_share", "flows_per_server"]
MIXED_APPS = {"bilibili", "youtube", "tencent_video", "iqiyi", "youku", "xigua", "kuaishou"}  # vod and live on one domain set
MIN_BYTES = 20_000  # windows with less downlink are not classified


def _group(r: dict) -> str:
    app = r.get("app") or "unknown"
    if app in ("unknown", "other") or app.startswith("ndpi:"):
        return "srv:" + r["server"]
    return app


def slices(rows: list[dict], window: float = 30.0, step: float = 15.0) -> list[dict]:
    """Feature rows, one per (UE, group, window) with enough traffic."""
    rows = [r for r in rows if not (r["server_port"] == 53)]
    groups = defaultdict(list)
    for r in rows:
        groups[(r["ue"], _group(r))].append(r)
    out = []
    W = int(window)
    for (ue, grp), fl in groups.items():
        t0 = math.floor(min(r["start"] for r in fl))
        t1 = max(r["end"] for r in fl)
        w = float(t0)
        while w < t1:
            active = [r for r in fl if r["start"] < w + W and r["end"] >= w]
            if active:
                feat = _features(active, w, W)
                if feat is not None:
                    top = max(active, key=lambda r: _bytes_in(r, w, W))
                    out.append({"ue": ue, "group": grp, "app": fl[0].get("app") or "unknown",
                                "category": fl[0].get("category") or "other", "t0": w, "t1": w + W,
                                "top_server": top["server"], **feat})
            w += step
    return out


def _series(r: dict, key: str, w: float, W: int) -> np.ndarray:
    s = np.zeros(W)
    base = math.floor(r["start"])
    for k, v in enumerate(r.get(key) or []):
        i = base + k - int(w)
        if 0 <= i < W:
            s[i] += v
    return s


def _bytes_in(r: dict, w: float, W: int) -> float:
    return float(_series(r, "rate_down", w, W).sum())


def _features(active: list[dict], w: float, W: int) -> dict | None:
    down = np.zeros(W)
    up = np.zeros(W)
    per_flow = []
    for r in active:
        d = _series(r, "rate_down", w, W)
        down += d
        up += _series(r, "rate_up", w, W)
        per_flow.append((float(d.sum()), r))
    total = down.sum()
    if total < MIN_BYTES:
        return None
    mask = pacing.busy(down)
    on, off = pacing.runs(mask)
    x = down / (down.max() or 1)
    acf = 0.0
    if x.std() > 0:
        xc = x - x.mean()
        den = float((xc * xc).sum())
        acf = max(float((xc[:-k] * xc[k:]).sum()) / den for k in range(1, min(9, W - 1)))
    top_b, top = max(per_flow, key=lambda t: t[0])
    top_mask = pacing.busy(_series(top, "rate_down", w, W))
    starts = [i for i in range(W) if mask[i] and (i == 0 or not mask[i - 1])]
    sizes = [-v for r in active for v in (r.get("seq_len") or []) if v < 0]
    quic = sum(b for b, r in per_flow if r.get("quic_version"))
    servers = len({r["server"] for r in active})
    return {
        "idle_frac": float(1 - mask.mean()),
        "cv": float(down.std() / (down.mean() or 1)),
        "peak3_share": float(np.sort(down)[-3:].sum() / total),
        "acf_max": acf,
        "on_runs": len(on) / W * 30,
        "on_mean": float(np.mean(on)) if on else 0.0,
        "off_mean": float(np.mean(off)) if off else 0.0,
        "longest_on": (max(on) if on else 0) / W,
        "busy_period": float(np.median(np.diff(starts))) if len(starts) > 1 else float(W),
        "up_down": float(up.sum() / total),
        "flows_started": sum(1 for r in active if r["start"] >= w),
        "top_share": top_b / total,
        "top_age": min((w + W - top["start"]) / W, 10.0),
        "top_busy": float(top_mask.mean()),
        "full_pkt_share": float(np.mean([s >= 1200 for s in sizes])) if sizes else 0.0,
        "small_pkt_share": float(np.mean([s <= 100 for s in sizes])) if sizes else 0.0,
        "quic_share": quic / total,
        "flows_per_server": len(active) / servers,
    }


# ---------------------------------------------------------------- labels


def _time(v: str) -> float:
    """Unix seconds, or a local wall-clock time such as 2026-11-10 14:05:00."""
    try:
        return float(v)
    except ValueError:
        return datetime.fromisoformat(v.strip()).timestamp()


def read_truth(spec: str | Path, anon: Anonymizer | None = None) -> list[dict]:
    """Service intervals.

    spec is a service name (the whole capture is that service), or a CSV: an action log
    (t_start,t_end,service[,app]), synth's actions.csv (start,end,service,ue_ip), or a hand-written log
    (start,end,service[,app]) with Unix seconds or local times.
    """
    if str(spec) in SERVICES:
        return [{"t0": -math.inf, "t1": math.inf, "service": str(spec), "ue": None, "app": None}]
    with open(spec, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        if not r.get("service"):
            continue
        if r["service"] not in SERVICES:
            raise ValueError(f"{spec}: unknown service {r['service']!r}, use one of {', '.join(SERVICES)}")
        ue = None
        if r.get("ue_ip") and anon is not None:
            ue = anon.ip(ipaddress.ip_address(r["ue_ip"]).packed)
        out.append({"t0": _time(r.get("t_start") or r["start"]), "t1": _time(r.get("t_end") or r["end"]),
                    "service": r["service"], "ue": ue, "app": (r.get("app") or "").strip() or None})
    return out


NEUTRAL = {"video", "short_video", "live_streaming", "cdn", "web", "other"}  # categories a media session can show up as


def _fits(s: dict, t: dict) -> bool:
    """Does a truth interval speak for this slice? Background apps (chat, updates, ads) keep no label."""
    if t["ue"] is not None and t["ue"] != s["ue"]:
        return False
    if t["service"] == "other" or s["group"].startswith("srv:"):
        return True
    if t.get("app"):
        return s["app"] == t["app"] or s["category"] in ("cdn", "other")
    return s["category"] in NEUTRAL


def label_truth(sl: list[dict], truth: list[dict]) -> None:
    for s in sl:
        cover = Counter()
        for t in truth:
            if not _fits(s, t):
                continue
            ov = min(s["t1"], t["t1"]) - max(s["t0"], t["t0"])
            if ov > 0:
                cover[t["service"]] += ov
        s["label"] = cover.most_common(1)[0][0] if cover else None


def label_weak(sl: list[dict]) -> None:
    for s in sl:
        if s["app"] in MIXED_APPS:
            s["label"] = None
        else:
            s["label"] = SERVICE_OF_CATEGORY.get(s["category"], "other") if not s["group"].startswith("srv:") else None


# ---------------------------------------------------------------- model


def _lgb():
    try:
        import lightgbm
    except (ImportError, OSError) as e:  # OSError: libomp missing on macOS
        raise RuntimeError("LightGBM is not available; pip install 'upsynth[ml]' (macOS also needs: brew install libomp)") from e
    return lightgbm


def _matrix(sl: list[dict]) -> np.ndarray:
    return np.array([[s[f] for f in FEATURES] for s in sl], dtype=float)


def fit(sl: list[dict], seed: int = 0):
    lgb = _lgb()
    y = np.array([SERVICES.index(s["label"]) for s in sl])
    counts = np.bincount(y, minlength=len(SERVICES))
    weight = np.array([len(y) / (len(SERVICES) * counts[c]) for c in y])  # balanced classes
    params = {"objective": "multiclass", "num_class": len(SERVICES), "learning_rate": 0.05, "num_leaves": 15,
              "min_data_in_leaf": 5, "feature_fraction": 0.9, "bagging_fraction": 0.9, "bagging_freq": 1,
              "seed": seed, "verbose": -1}
    return lgb.train(params, lgb.Dataset(_matrix(sl), label=y, weight=weight, feature_name=FEATURES),
                     num_boost_round=200)


def predict(booster, sl: list[dict]) -> np.ndarray:
    return booster.predict(_matrix(sl)) if sl else np.zeros((0, len(SERVICES)))


def scores(y_true: list[str], y_pred: list[str]) -> dict:
    present = [c for c in SERVICES if c in y_true]
    f1s = {}
    for c in present:
        tp = sum(1 for a, b in zip(y_true, y_pred) if a == c and b == c)
        fp = sum(1 for a, b in zip(y_true, y_pred) if a != c and b == c)
        fn = sum(1 for a, b in zip(y_true, y_pred) if a == c and b != c)
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f1s[c] = round(2 * p * r / (p + r), 3) if p + r else 0.0
    conf = {a: dict(Counter(p for t, p in zip(y_true, y_pred) if t == a)) for a in present}
    return {"n": len(y_true), "accuracy": round(sum(a == b for a, b in zip(y_true, y_pred)) / max(len(y_true), 1), 3),
            "macro_f1": round(float(np.mean(list(f1s.values()))), 3) if f1s else 0.0, "f1": f1s, "confusion": conf}


def holdout_groups(sl: list[dict], by: str) -> list[str]:
    if by == "region":
        return [s["region"] for s in sl]
    if by == "app":
        return [s["app"] for s in sl]
    # time: 5-minute blocks per region, so overlapping windows of one session stay on one side
    return [f"{s['region']}:{int(s['t0'] // 300)}" for s in sl]


def evaluate(sl: list[dict], by: str, seed: int = 0, folds: int = 5) -> dict:
    groups = holdout_groups(sl, by)
    uniq = sorted(set(groups))
    if len(uniq) < 2:
        return {"holdout": by, "error": f"need at least two {by} groups"}
    if by == "time" and len(uniq) > folds:
        rng = np.random.default_rng(seed)
        perm = list(rng.permutation(uniq))
        assign = {g: i % folds for i, g in enumerate(perm)}
        groups = [str(assign[g]) for g in groups]
        uniq = sorted(set(groups))
    y_true, y_pred, per = [], [], {}
    for g in uniq:
        train = [s for s, h in zip(sl, groups) if h != g]
        test = [s for s, h in zip(sl, groups) if h == g]
        if len({s["label"] for s in train}) < 2 or not test:
            continue
        booster = fit(train, seed)
        pred = [SERVICES[i] for i in predict(booster, test).argmax(1)]
        truth = [s["label"] for s in test]
        per[g] = scores(truth, pred)
        y_true += truth
        y_pred += pred
    return {"holdout": by, "overall": scores(y_true, y_pred), "per_group": per}


# ---------------------------------------------------------------- commands


def load_slices(data: list[tuple[str, str, str | None]], *, key: bytes, window: float, step: float) -> list[dict]:
    """data: (region, labeled.parquet, truth.csv or a service name or None)."""
    anon = Anonymizer(key)
    out = []
    for region, path, truth in data:
        sl = slices(pq.read_table(path).to_pylist(), window, step)
        if truth:
            label_truth(sl, read_truth(truth, anon))
        else:
            label_weak(sl)
        for s in sl:
            s["region"] = region
        out += sl
    return out


def train(data: list[tuple[str, str, str | None]], model_out: str | Path, *, key: bytes, window: float = 30.0,
          step: float = 15.0, holdout: list[str] | None = None, seed: int = 0) -> dict:
    sl = [s for s in load_slices(data, key=key, window=window, step=step) if s.get("label")]
    if len({s["label"] for s in sl}) < 2:
        raise ValueError("need labeled slices of at least two services")
    res = {"slices": len(sl), "by_label": dict(Counter(s["label"] for s in sl)),
           "by_region": dict(Counter(s["region"] for s in sl)), "features": FEATURES}
    res["evaluation"] = [evaluate(sl, by, seed) for by in (holdout or [])]
    booster = fit(sl, seed)
    Path(model_out).parent.mkdir(parents=True, exist_ok=True)
    meta = {"features": FEATURES, "classes": list(SERVICES), "window": window, "step": step,
            "model": booster.model_to_string()}
    Path(model_out).write_text(json.dumps(meta), encoding="utf-8")
    imp = booster.feature_importance("gain")
    res["feature_importance"] = dict(sorted(((f, round(float(v), 1)) for f, v in zip(FEATURES, imp)),
                                            key=lambda kv: -kv[1])[:8])
    res["model"] = str(model_out)
    return res


def classify(labeled: str | Path, model: str | Path, out: str | Path, *, truth: str | None = None,
             key: bytes | None = None) -> dict:
    lgb = _lgb()
    meta = json.loads(Path(model).read_text(encoding="utf-8"))
    booster = lgb.Booster(model_str=meta["model"])
    sl = slices(pq.read_table(labeled).to_pylist(), meta["window"], meta["step"])
    prob = predict(booster, sl)
    classes = meta["classes"]
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ue", "group", "app", "t0", "t1", "service", *[f"p_{c}" for c in classes]])
        for s, p in zip(sl, prob):
            w.writerow([s["ue"], s["group"], s["app"], f"{s['t0']:.0f}", f"{s['t1']:.0f}", classes[int(p.argmax())],
                        *[f"{x:.3f}" for x in p]])
    res = {"input": str(labeled), "output": str(out), "slices": len(sl),
           "by_service": dict(Counter(classes[int(p.argmax())] for p in prob))}
    if truth:
        label_truth(sl, read_truth(truth, Anonymizer(key) if key else None))
        pairs = [(s["label"], classes[int(p.argmax())]) for s, p in zip(sl, prob) if s.get("label")]
        if pairs:
            res["vs_truth"] = scores([a for a, _ in pairs], [b for _, b in pairs])
    return res
