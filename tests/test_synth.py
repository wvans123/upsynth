import csv
import hashlib
import subprocess

import pyarrow.parquet as pq
import pytest

from upsynth import ingest, label, synth
from upsynth.synth.check import tshark_check

from .conftest import KEY


@pytest.fixture(scope="module")
def synth_n3(work):
    res = synth.run(work / "profile.json", work / "out_n3.pcap", ues=4, duration=90, iface="n3", seed=1, check=False)
    return res


def _labels(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_writes_pcap_and_labels(work, synth_n3):
    assert synth_n3["frames"] > 1000
    rows = _labels(synth_n3["labels"])
    assert len(rows) == synth_n3["flows"] + synth_n3["dns_lookups"]
    assert {r["ue"] for r in rows} <= {"ue1", "ue2", "ue3", "ue4"}
    for r in rows:
        assert float(r["start"]) <= float(r["end"])
        assert r["teid_ul"].startswith("0x")
    assert sum(int(r["packets"]) for r in rows) == synth_n3["frames"]


def test_same_seed_same_pcap(work, tmp_path):
    a = synth.run(work / "profile.json", tmp_path / "a.pcap", ues=2, duration=30, seed=5, check=False)
    b = synth.run(work / "profile.json", tmp_path / "b.pcap", ues=2, duration=30, seed=5, check=False)
    ha = hashlib.sha256((tmp_path / "a.pcap").read_bytes()).hexdigest()
    hb = hashlib.sha256((tmp_path / "b.pcap").read_bytes()).hexdigest()
    assert a["frames"] == b["frames"] and ha == hb


def test_roundtrip_ingest_recovers_names_and_fingerprints(work, synth_n3, tmp_path):
    """What synth claims in labels.csv is what ingest + label read back from the packets."""
    ingest.run(work / "out_n3.pcap", tmp_path / "f.parquet", key=KEY)
    label.run(tmp_path / "f.parquet", tmp_path / "l.parquet")
    got = pq.read_table(tmp_path / "l.parquet").to_pylist()
    rows = _labels(synth_n3["labels"])
    want_tls = {(r["domain"], r["ja4"]) for r in rows if r["ja4"]}
    have_tls = {(r["sni"], r["ja4"]) for r in got if r["ja4"]}
    assert want_tls == have_tls
    assert len(got) == len(rows)
    by_app_want = sorted(r["app"] for r in rows if not r["domain"].endswith(".example.net"))
    by_app_have = sorted(r["app"] for r in got if not (r["sni"] or "").endswith(".example.net"))
    assert by_app_want == by_app_have


def test_app_filter_and_n6(work, tmp_path):
    res = synth.run(work / "profile.json", tmp_path / "n6.pcap", ues=2, duration=60, iface="n6", apps=["youtube"],
                    seed=2, check=False)
    assert set(res["by_app"]) == {"youtube"}
    with pytest.raises(ValueError):
        synth.run(work / "profile.json", tmp_path / "x.pcap", apps=["nope"], check=False)


def test_tshark_zero_malformed(work, synth_n3, tshark, tmp_path):
    r = tshark_check(work / "out_n3.pcap", tshark)
    assert r["frames"] == synth_n3["frames"]
    assert r["malformed"] == 0, r["examples"]
    n6 = synth.run(work / "profile.json", tmp_path / "n6.pcap", ues=4, duration=90, iface="n6", seed=3, check=True)
    assert n6["check"]["malformed"] == 0, n6["check"]["examples"]
    sample = tshark_check(work / "sample_n3.pcap", tshark)
    assert sample["malformed"] == 0, sample["examples"]


def test_tshark_sees_our_fields(work, synth_n3, tshark):
    """Wireshark decodes the GTP-U QFI, SNI and JA4 the labels claim."""
    out = subprocess.run([tshark, "-n", "-r", str(work / "out_n3.pcap"), "-Y", "tls.handshake.type == 1",
                          "-T", "fields", "-e", "tls.handshake.extensions_server_name", "-e", "tls.handshake.ja4"],
                         capture_output=True, text=True, check=True).stdout
    seen = {tuple(line.split("\t")) for line in out.splitlines() if line}
    rows = _labels(synth_n3["labels"])
    want = {(r["domain"], r["ja4"]) for r in rows if r["ja4"]}
    if all(len(s) == 2 and s[1] for s in seen):  # tshark >= 4.2 has tls.handshake.ja4
        assert seen == want
    else:
        assert {s[0] for s in seen} == {d for d, _ in want}
    qfi = subprocess.run([tshark, "-n", "-r", str(work / "out_n3.pcap"), "-c", "50", "-T", "fields",
                          "-e", "gtp.ext_hdr.pdu_ses_con.qos_flow_id"], capture_output=True, text=True, check=True).stdout
    assert {q for q in qfi.split() if q}
