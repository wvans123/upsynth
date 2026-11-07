import json

import pytest
from typer.testing import CliRunner

from upsynth.cli import app

runner = CliRunner()


@pytest.mark.parametrize("cmd", ["ingest", "label", "profile", "synth", "kb"])
def test_help(cmd):
    r = runner.invoke(app, [cmd, "--help"])
    assert r.exit_code == 0
    assert "--json" in r.output


def test_full_pipeline_json(work, tmp_path):
    def run(*args):
        r = runner.invoke(app, [*args, "--json"])
        assert r.exit_code == 0, r.output
        return json.loads(r.output)

    a = run("ingest", str(work / "sample_n3.pcap"), "-o", str(tmp_path / "f.parquet"), "--key", "k")
    assert a["flows"] == 106
    b = run("label", str(tmp_path / "f.parquet"), "-o", str(tmp_path / "l.parquet"))
    assert b["labeled"] == 106
    c = run("profile", str(tmp_path / "l.parquet"), "-o", str(tmp_path / "p.json"), "--min-flows", "3")
    assert "youtube" in c["apps"]
    d = run("synth", str(tmp_path / "p.json"), "-o", str(tmp_path / "o.pcap"), "--ues", "2", "--duration", "20",
            "--no-check")
    assert d["frames"] > 0


def test_kb_find_and_errors(tmp_path):
    r = runner.invoke(app, ["kb", "--find", "www.bilibili.com", "--json"])
    assert json.loads(r.output)["find"]["app"] == "bilibili"
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a pcap at all")
    r = runner.invoke(app, ["ingest", str(bad), "-o", str(tmp_path / "x.parquet"), "--key", "k", "--json"])
    assert r.exit_code == 1 and "error" in json.loads(r.output)
