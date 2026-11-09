"""End-to-end run of the method on lab data.

  capture A (pcap + action log) -> profile with actions -> synthetic traffic for three imitated regions
  -> behaviour classifier -> scores on held-out synthetic regions and on capture B (real, never used
  for the profile)

Usage: python run_experiment.py A.pcap A.csv B.pcap B.csv <workdir> [--ues 10] [--minutes 12]

Regions are imitated by delay, bandwidth and CDN region codes (synth --rtt-ms / --bw-mbps /
--cdn-region). With real captures from several regions the same classify.train call takes them, and
--holdout region becomes the real test.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from upsynth import classify, ingest, label, profile, synth
from upsynth.anon import load_key

REGIONS = {
    "shanghai": {"rtt_ms": 0.0, "bw_mbps": None, "cdn_region": "shsh-ct", "seed": 1},
    "jiangsu": {"rtt_ms": 15.0, "bw_mbps": 30.0, "cdn_region": "jsnj-cu", "seed": 2},
    "north": {"rtt_ms": 40.0, "bw_mbps": 15.0, "cdn_region": "bjbj-cm", "seed": 3},
}


def labeled(pcap: str, w: Path, name: str, key: bytes) -> str:
    ingest.run(pcap, w / f"{name}_flows.parquet", key=key)
    label.run(w / f"{name}_flows.parquet", w / f"{name}_labeled.parquet")
    return str(w / f"{name}_labeled.parquet")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("a_pcap")
    ap.add_argument("a_actions")
    ap.add_argument("b_pcap")
    ap.add_argument("b_actions")
    ap.add_argument("work")
    ap.add_argument("--ues", type=int, default=10)
    ap.add_argument("--minutes", type=float, default=12)
    ap.add_argument("--script", help="also play this action script (e.g. one an LLM wrote from a persona)")
    a = ap.parse_args()
    w = Path(a.work)
    w.mkdir(parents=True, exist_ok=True)
    key = load_key(None)
    rep: dict = {}

    lab_a = labeled(a.a_pcap, w, "lab_a", key)
    lab_b = labeled(a.b_pcap, w, "lab_b", key)
    rep["profile"] = profile.run(lab_a, w / "profile.json", min_flows=3, actions=a.a_actions)

    syn = []
    for name, knobs in REGIONS.items():
        r = synth.run(w / "profile.json", w / f"syn_{name}.pcap", ues=a.ues, duration=a.minutes * 60,
                      mode="actions", check=False, **knobs)
        syn.append((name, labeled(r["output"], w, f"syn_{name}", key), r["actions_csv"]))
        rep.setdefault("synth", {})[name] = {k: r[k] for k in ("flows", "frames", "actions")}

    real_a = [("lab_a", lab_a, a.a_actions)]
    runs = {"real_A": real_a, "synthetic": syn, "synthetic+real_A": syn + real_a}
    rep["held_out_region"] = classify.train(syn, w / "model_syn.json", key=key, holdout=["region"])["evaluation"][0]
    rep["test_on_B"] = {}
    for name, data in runs.items():
        classify.train(data, w / f"model_{name}.json", key=key)
        rep["test_on_B"][name] = classify.classify(lab_b, w / f"model_{name}.json", w / f"B_{name}.csv",
                                                   truth=a.b_actions)["vs_truth"]
    if a.script:
        r = synth.run(w / "profile.json", w / "script.pcap", ues=1, duration=a.minutes * 60, script=a.script)
        rep["script"] = {k: r[k] for k in ("flows", "frames", "actions", "check", "script_dwell_outside_profile")}
    (w / "report.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False, default=str), encoding="utf-8")

    h = rep["held_out_region"]
    print("held-out synthetic region, macro-F1:", h["overall"]["macro_f1"],
          {g: v["macro_f1"] for g, v in h["per_group"].items()})
    for name, s in rep["test_on_B"].items():
        print(f"real capture B, trained on {name:17s} macro-F1 {s['macro_f1']}  (n={s['n']})  f1={s['f1']}")


if __name__ == "__main__":
    main()
