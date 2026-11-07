"""Port-aware payloads: every codec and the port remapping keep tshark free of malformed packets."""

import random

import pytest

from upsynth.label import load_kb
from upsynth.schemas import Categorical, Hist, Profile
from upsynth import synth
from upsynth.synth import protocols


def test_registry_and_fits():
    reg = protocols.load_registry(None)
    assert reg[("tcp", 443)] == "tls" and reg[("udp", 1194)] == "openvpn"
    assert protocols.fits("tls_tcp", 443, reg)
    assert protocols.fits("tcp", 1883, reg)  # MQTT codec
    assert not protocols.fits("tcp", 1194, reg)  # opaque bytes on the OpenVPN port
    assert not protocols.fits("tls_tcp", 6000, reg)  # X11
    assert protocols.fits("udp", 51820, reg)
    assert protocols.fits("udp", 45678, reg) or ("udp", 45678) in reg
    p = protocols.free_port("udp", 19132, reg)
    assert ("udp", p) not in reg and p == protocols.free_port("udp", 19132, reg)


def _profile(work, specs) -> Profile:
    """One app per (transport, port), copied from an app of the sample profile."""
    base = Profile.model_validate_json((work / "profile.json").read_text())
    tm = {a.app: a for a in base.apps}
    apps = []
    for transport, port in specs:
        ap = (tm["zoom"] if transport in ("udp", "quic") else tm["wechat"]).model_copy(deep=True)
        ap.app = f"{transport}_{port}"
        ap.category = "other"
        ap.transport = Categorical(values=[transport], probs=[1.0])
        ap.endpoints = Categorical(values=[f"{transport}/{port}"], probs=[1.0])
        ap.domains = Categorical(values=["x.example.org"], probs=[1.0])
        ap.concurrency = Hist(edges=[1, 2], probs=[1.0])
        ap.pkts_up = ap.pkts_down = Hist(edges=[8, 16], probs=[1.0])
        ap.flow_share = 1 / len(specs)
        apps.append(ap)
    base.apps = apps
    base.app_transitions = {}
    u = base.ues[0]
    u.app_mix = Categorical(values=[a.app for a in apps], probs=[1 / len(apps)] * len(apps))
    u.session_flows = Hist(edges=[len(specs) * 2, len(specs) * 2 + 1], probs=[1.0])
    u.inter_flow = Hist(edges=[0.01, 0.02], probs=[1.0])
    base.ues = [u]
    return base


def test_codec_ports_and_kb_ports(work, tshark, tmp_path):
    specs = set()
    for port in protocols.TCP_CODECS:
        specs |= {("tcp", port), ("tls_tcp", port)}
    for port in protocols.UDP_CODECS:
        specs.add(("udp", port))
    for a in load_kb().apps:
        for p in a.ports:
            proto, _, rng = p.partition("/")
            lo, _, hi = rng.partition("-")
            for port in {int(lo), int(hi or lo)}:
                specs |= {("tcp", port), ("tls_tcp", port)} if proto == "tcp" else {("udp", port), ("quic", port)}
    prof = _profile(work, sorted(specs))
    (tmp_path / "p.json").write_text(prof.model_dump_json())
    for iface in ("n3", "n6"):
        r = synth.run(tmp_path / "p.json", tmp_path / f"{iface}.pcap", ues=1, duration=30, iface=iface, seed=11)
        assert r["check"]["malformed"] == 0, r["check"]["examples"]
        assert r["check"]["expert_errors"] == 0, r["check"]["examples"]


def test_random_registered_ports(work, tshark, tmp_path):
    reg = protocols.load_registry(tshark)
    ports = sorted(reg)
    random.Random(3).shuffle(ports)
    specs = []
    for proto, port in ports[:150]:
        specs += [("tcp", port), ("tls_tcp", port)] if proto == "tcp" else [("udp", port), ("quic", port)]
    prof = _profile(work, specs)
    (tmp_path / "p.json").write_text(prof.model_dump_json())
    r = synth.run(tmp_path / "p.json", tmp_path / "o.pcap", ues=1, duration=60, iface="n6", seed=4)
    assert r["check"]["malformed"] == 0, r["check"]["examples"]
    assert r["ports_remapped"]


@pytest.mark.parametrize("n", [1, 2, 5, 11, 12, 13, 129, 130, 131, 16385, 16386, 70000])
def test_mqtt_fill_is_valid(n):
    r = protocols.Rnd(__import__("numpy").random.default_rng(n))
    data = protocols._mqtt_publish_fill(r, n)
    assert n - 2 <= len(data) <= n
    p = 0
    while p < len(data):  # walk the packets: fixed header + remaining length
        p += 1
        mult, rl = 1, 0
        while True:
            b = data[p]
            p += 1
            rl += (b & 0x7F) * mult
            mult *= 128
            if not b & 0x80:
                break
        p += rl
    assert p == len(data)
