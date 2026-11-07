"""The real Open5GS + UERANSIM capture in examples/."""

import subprocess
from pathlib import Path

import pyarrow.parquet as pq
import pytest

from upsynth import ingest, label, synth

EX = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture(scope="module")
def real(tmp_path_factory):
    d = tmp_path_factory.mktemp("real")
    r3 = ingest.run(EX / "open5gs_n3.pcap", d / "n3.parquet", key=b"k")
    r6 = ingest.run(EX / "open5gs_n6.pcap", d / "n6.parquet", key=b"k")
    lab = label.run(d / "n3.parquet", d / "labeled.parquet")
    return d, r3, r6, lab


def test_real_n3(real):
    d, r3, _, _ = real
    assert r3["gtpu_packets"] == r3["frames"] and r3["flows_n3"] == r3["flows"] == 600
    assert r3["with_sni"] == 438 and r3["with_dns_name"] == 448
    rows = pq.read_table(d / "n3.parquet").to_pylist()
    assert {r["qfi"] for r in rows} == {1}
    assert len({r["teid_ul"] for r in rows}) == 1 and len({r["ue"] for r in rows}) == 1


def test_n3_and_n6_agree(real):
    """The same flows seen inside GTP-U on N3 and as plain IP on N6."""
    d, r3, r6, _ = real
    assert r6["flows_n6"] == r3["flows"]
    key = lambda r: (r["proto"], r["ue_port"], r["server_port"], r["server"], r["sni"], r["dns_name"], r["ja4"])
    a = sorted(map(key, pq.read_table(d / "n3.parquet").to_pylist()))
    b = sorted(map(key, pq.read_table(d / "n6.parquet").to_pylist()))
    assert a == b


def test_real_labels(real):
    _, _, _, lab = real
    assert lab["labeled"] / lab["flows"] >= 0.95
    for app in ("jd", "baidu", "bilibili", "zhihu", "netease", "github", "dns", "ntp"):
        assert app in lab["by_app"], app


def test_real_reconciles_with_tshark(real, tshark):
    d = real[0]
    out = subprocess.run([tshark, "-n", "-r", str(EX / "open5gs_n3.pcap"), "-Y", "tls.handshake.type == 1",
                          "-T", "fields", "-e", "tls.handshake.extensions_server_name"],
                         capture_output=True, text=True, check=True).stdout
    rows = pq.read_table(d / "n3.parquet").to_pylist()
    assert {s for s in out.split() if s} == {r["sni"] for r in rows if r["sni"]}
    # Wireshark's own JA4 for real clients (wget over TCP, aioquic over QUIC) equals ours
    ja4 = subprocess.run([tshark, "-n", "-r", str(EX / "open5gs_n3.pcap"), "-Y", "tls.handshake.type == 1",
                          "-T", "fields", "-e", "tls.handshake.ja4"], capture_output=True, text=True, check=True).stdout
    ours = {r["ja4"] for r in rows if r["ja4"]}
    assert {s for s in ja4.split() if s} == ours and any(j.startswith("q") for j in ours)


def test_synth_from_real_profile(tshark, tmp_path):
    r = synth.run(EX / "open5gs_profile.json", tmp_path / "o.pcap", ues=3, duration=60, seed=9)
    assert r["check"]["malformed"] == 0 and r["check"]["expert_errors"] == 0, r["check"]["examples"]
    assert r["frames"] > 10000
