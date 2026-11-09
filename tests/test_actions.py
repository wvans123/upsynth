import csv
import json

import pyarrow.parquet as pq
import pytest

from upsynth import actions, profile, synth
from upsynth.schemas import Profile


@pytest.fixture(scope="module")
def log_profile(work, tmp_path_factory):
    """An action log over the sample: every flow start opens an action named after its app."""
    d = tmp_path_factory.mktemp("act")
    rows = [r for r in pq.read_table(work / "labeled.parquet").to_pylist() if r["server_port"] != 53]
    rows.sort(key=lambda r: r["start"])
    with open(d / "actions.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t_start", "t_end", "app", "action", "service"])
        t_prev = None
        for r in rows:
            if t_prev is None or r["start"] - t_prev > 2:
                w.writerow([r["start"] - 0.01, r["start"] + 1, "demo", "use_" + r["app"],
                            "vod" if r["app"] == "youtube" else "other"])
                t_prev = r["start"]
    profile.run(work / "labeled.parquet", d / "profile.json", min_flows=3, actions=d / "actions.csv")
    return d


def test_action_model_from_log(log_profile):
    prof = Profile.model_validate_json((log_profile / "profile.json").read_text())
    m = prof.action_model
    assert m.source == "log" and m.actions
    yt = next(a for a in m.actions if a.name == "demo/use_youtube")
    assert yt.service == "vod"
    assert any(s.app == "youtube" for s in yt.slots)
    assert all(0 < s.p <= 1 for a in m.actions for s in a.slots)
    assert actions.resolve(m, "use_youtube") == "demo/use_youtube"
    with pytest.raises(ValueError, match="the profile has"):
        actions.resolve(m, "nope")


def test_bursts_model(work, tmp_path):
    profile.run(work / "labeled.parquet", tmp_path / "p.json", min_flows=3, actions="bursts", action_types=4)
    prof = Profile.model_validate_json((tmp_path / "p.json").read_text())
    assert prof.action_model.source == "bursts"
    assert all("/b" in a.name for a in prof.action_model.actions)


def test_synth_actions_mode_and_script(log_profile, tmp_path):
    r = synth.run(log_profile / "profile.json", tmp_path / "a.pcap", ues=2, duration=60, mode="actions", seed=3,
                  check=False)
    assert r["mode"] == "actions" and r["actions"] > 0
    rows = list(csv.DictReader(open(r["labels"])))
    assert all(x["action"] for x in rows if x["app"] != "dns") and {x["service"] for x in rows} <= {"vod", "other"}
    acts = list(csv.DictReader(open(r["actions_csv"])))
    assert {"ue_ip", "service", "start", "end"} <= set(acts[0])

    script = {"sessions": [{"persona": "test", "ue": "ue1", "steps": [
        {"action": "use_youtube", "dwell": 20}, {"action": "use_wechat"}, {"action": "use_youtube", "dwell": 15}]}]}
    (tmp_path / "s.json").write_text(json.dumps(script))
    r = synth.run(log_profile / "profile.json", tmp_path / "s.pcap", ues=1, duration=120, script=tmp_path / "s.json",
                  seed=4, check=False)
    acts = list(csv.DictReader(open(r["actions_csv"])))
    assert [a["action"] for a in acts] == ["demo/use_youtube", "demo/use_wechat", "demo/use_youtube"]
    assert abs(float(acts[1]["start"]) - float(acts[0]["start"]) - 20) < 1e-6
    assert r["script_dwell_outside_profile"] >= 1
    bad = {"sessions": [{"steps": [{"action": "nope"}]}]}
    (tmp_path / "bad.json").write_text(json.dumps(bad))
    with pytest.raises(ValueError, match="unknown action"):
        synth.run(log_profile / "profile.json", tmp_path / "b.pcap", script=tmp_path / "bad.json", check=False)


def test_actions_command(log_profile):
    from typer.testing import CliRunner

    from upsynth.cli import app

    r = CliRunner().invoke(app, ["actions", str(log_profile / "profile.json"), "--json"])
    d = json.loads(r.output)
    assert d["source"] == "log" and any(a["action"] == "demo/use_youtube" for a in d["actions"])
    assert "sessions" in d["script_example"]
