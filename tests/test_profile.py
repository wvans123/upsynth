import json

import numpy as np
import pyarrow.parquet as pq

from upsynth import profile
from upsynth.schemas import Profile


def test_profile_valid_and_distribution_only(work):
    text = (work / "profile.json").read_text()
    prof = Profile.model_validate_json(text)
    assert prof.meta.flows == 58 and prof.meta.ues == 3
    assert abs(sum(a.flow_share for a in prof.apps) - 1) < 1e-3
    for a in prof.apps:
        for h in (a.duration, a.pkts_up, a.bytes_down, a.len_up, a.iat, a.concurrency):
            assert len(h.edges) == len(h.probs) + 1
            assert abs(sum(h.probs) - 1) < 1e-3
        assert a.chain is None or all(abs(sum(r) - 1) < 1e-3 for r in a.chain.trans)
    # no UE / server tokens, no addresses
    rows = pq.read_table(work / "labeled.parquet").to_pylist()
    for tok in {r["ue"] for r in rows} | {r["server"] for r in rows}:
        assert tok not in text
    assert "10.45." not in text and "198.18." not in text
    assert [u.ue for u in prof.ues] == ["ue1", "ue2", "ue3"]


def test_domains_only_from_kb_matches(work):
    prof = json.loads((work / "profile.json").read_text())
    yt = next(a for a in prof["apps"] if a["app"] == "youtube")
    assert "rr3---sn-a5mekn6r.googlevideo.com" in yt["domains"]["values"]
    assert set(yt["transport"]["values"]) == {"quic", "tls_tcp"}
    assert set(yt["endpoints"]["values"]) == {"quic/443", "tls_tcp/443"}
    ntp = next(a for a in prof["apps"] if a["app"] == "ntp")
    assert ntp["endpoints"]["values"] == ["udp/123"]
    assert all(v.startswith(("t13", "q13")) for v in yt["ja4_r"]["values"])


def test_rare_apps_fold_into_other(work):
    rows = pq.read_table(work / "labeled.parquet").to_pylist()
    prof = profile.build(rows, min_flows=6)
    names = {a.app for a in prof.apps}
    assert "other" in names and "bbc" not in names  # bbc has 5 flows
    other = next(a for a in prof.apps if a.app == "other")
    assert other.domains.values == []


def test_kmeans_separates_clusters():
    rng = np.random.default_rng(0)
    x = np.vstack([rng.normal(0, 1, (20, 4)), rng.normal(100, 1, (20, 4))])
    c, labels = profile.kmeans(x, 2)
    assert len(set(labels[:20])) == 1 and len(set(labels[20:])) == 1 and labels[0] != labels[-1]
