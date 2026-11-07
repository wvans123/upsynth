from __future__ import annotations

import pytest

from upsynth import ingest, label, profile
from upsynth.sample import make_sample
from upsynth.synth.check import find_tshark

KEY = b"test-key"


@pytest.fixture(scope="session")
def work(tmp_path_factory):
    d = tmp_path_factory.mktemp("pipeline")
    make_sample(d / "sample_n3.pcap", iface="n3")
    make_sample(d / "sample_n6.pcap", iface="n6")
    ingest.run(d / "sample_n3.pcap", d / "flows.parquet", key=KEY)
    label.run(d / "flows.parquet", d / "labeled.parquet", pfd=d / "pfd.json")
    profile.run(d / "labeled.parquet", d / "profile.json", min_flows=3)
    return d


@pytest.fixture(scope="session")
def tshark():
    t = find_tshark()
    if not t:
        pytest.skip("tshark not installed")
    return t
