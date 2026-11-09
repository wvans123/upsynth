import numpy as np
import pytest

from upsynth import classify, pacing

pytest.importorskip("lightgbm")


def test_pacing_runs():
    m = pacing.busy([0, 0, 50000, 60000, 0, 0, 0, 55000, 0, 52000])
    assert pacing.runs(m) == ([2, 1, 1], [3, 1])
    t = pacing.timeline(np.random.default_rng(0), lambda: 2.0, lambda: 3.0, 20.0)
    assert t[0] == (0.0, 2.0) and t[1] == (5.0, 7.0)
    times = pacing.place(np.random.default_rng(0), t, 100)
    assert all(any(a <= x <= b for a, b in t) for x in times) and list(times) == sorted(times)


def _flow(ue, app, cat, start, series, server="s1"):
    return {"ue": ue, "app": app, "category": cat, "server": server, "server_port": 443, "start": float(start),
            "end": float(start + len(series)), "rate_down": [int(x) for x in series],
            "rate_up": [int(x * 0.03) for x in series], "seq_len": [60, -60, 52, 500, -1400, -1400, 52],
            "quic_version": None}


def _session(rng, kind, ue, t0, seconds=120):
    """Flows of one UE doing one thing for `seconds`, with the scale changed per region."""
    scale = rng.uniform(0.3, 3.0)  # bandwidth differs between regions; features must not care
    if kind == "live":
        return [_flow(ue, "huya", "live_streaming", t0, rng.normal(250e3, 25e3, seconds).clip(1e3) * scale)]
    if kind == "vod":
        s = np.zeros(seconds)
        for k in range(0, seconds, 10):
            s[k : k + 3] = rng.normal(900e3, 100e3, 3).clip(1e3) * scale
        return [_flow(ue, "iqiyi", "video", t0, s)]
    if kind == "short_video":
        out, t = [], t0
        while t < t0 + seconds:
            d = int(rng.integers(4, 9))
            s = np.r_[rng.normal(1.2e6, 1e5, 2), rng.normal(80e3, 1e4, d - 2)].clip(1e3) * scale
            out.append(_flow(ue, "douyin", "short_video", t, s, server=f"cdn{t}"))
            t += d
        return out
    out = []
    for t in range(t0, t0 + seconds, 6):
        out.append(_flow(ue, "zhihu", "social", t, rng.normal(30e3, 5e3, 2).clip(1e3) * scale, server=f"api{t}"))
    return out


def _region(rng, name):
    rows, truth = [], []
    for u in range(4):
        t = 1000
        for kind in ("live", "vod", "short_video", "other"):
            rows += _session(rng, kind, f"{name}-ue{u}", t)
            truth.append({"t0": t, "t1": t + 120, "service": kind, "ue": f"{name}-ue{u}"})
            t += 150
    return rows, truth


def test_classifier_generalises_across_regions():
    rng = np.random.default_rng(0)
    sl = []
    for name in ("shanghai", "jiangsu", "north"):
        rows, truth = _region(rng, name)
        s = classify.slices(rows)
        classify.label_truth(s, truth)
        for x in s:
            x["region"] = name
        sl += [x for x in s if x["label"]]
    assert {x["label"] for x in sl} == {"live", "vod", "short_video", "other"}
    ev = classify.evaluate(sl, "region")
    assert ev["overall"]["macro_f1"] >= 0.8, ev["overall"]
    assert set(ev["per_group"]) == {"shanghai", "jiangsu", "north"}


def test_weak_labels_skip_mixed_apps():
    s = [{"app": "huya", "category": "live_streaming", "group": "huya"},
         {"app": "bilibili", "category": "video", "group": "bilibili"},
         {"app": "unknown", "category": "other", "group": "srv:x"}]
    classify.label_weak(s)
    assert [x["label"] for x in s] == ["live", None, None]
