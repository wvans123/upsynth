import json

import pyarrow.parquet as pq
import pytest

from upsynth import label
from upsynth.schemas import CATEGORIES, LABELED_SCHEMA, KnowledgeBase


@pytest.fixture(scope="module")
def m():
    return label.Matcher(label.load_kb())


def test_kb_has_at_least_100_apps():
    kb = label.load_kb()
    assert len(kb.apps) >= 100
    assert all(a.category in CATEGORIES for a in kb.apps)


def test_longest_suffix_wins(m):
    assert m.by_name("mail.google.com") == "gmail"
    assert m.by_name("www.google.com") == "google_search"
    assert m.by_name("fonts.gstatic.com") == "google"
    assert m.by_name("rr1---sn-xyz.googlevideo.com") == "youtube"
    assert m.by_name("music.youtube.com") == "youtube_music"
    assert m.by_name("youtube.com") == "youtube"
    assert m.by_name("notyoutube.com") is None
    assert m.by_name("com") is None


def test_glob_beats_cdn_suffix(m):
    assert m.by_name("audio-ak-spotify-com.akamaized.net") == "spotify"
    assert m.by_name("something.akamaized.net") == "akamai"


def test_rule_order(m):
    base = {"proto": 6, "server_port": 443, "alpn": None, "sni": None, "http_host": None, "dns_name": None,
            "ja4": None, "asn": None, "ndpi_app": None}
    assert m.label({**base, "sni": "www.netflix.com", "dns_name": "x.wechat.com"})[:3] == ("netflix", "video", "sni")
    assert m.label({**base, "dns_name": "x.wechat.com"})[2] == "dns"
    assert m.label({**base, "asn": 2906})[:3] == ("netflix", "video", "asn")
    assert m.label({**base, "proto": 17, "server_port": 8805})[0] == "zoom"
    assert m.label({**base, "proto": 17, "server_port": 53, "sni": "www.netflix.com"})[0] == "dns"
    assert m.label({**base, "ndpi_app": "TLS.YouTube"})[:3] == ("youtube", "video", "ndpi")
    assert m.label({**base, "server_port": 80, "ndpi_app": "HTTP.Xiaomi"})[:3] == ("xiaomi", "app_store", "ndpi")
    assert m.label({**base, "server_port": 80})[:3] == ("web_http", "web", "port")
    assert m.label({**base, "ndpi_app": "TLS.SomethingNew"})[0] == "ndpi:TLS.SomethingNew"
    assert m.label(base)[:3] == ("unknown", "other", "none")


def test_alpn_narrows_a_port_rule(m):
    base = {"proto": 6, "server_port": 443, "sni": None, "http_host": None, "dns_name": None, "ja4": None,
            "asn": None, "ndpi_app": None}
    assert m.label({**base, "alpn": "apns-security-v3"})[:3] == ("apple_push_443", "other", "port")
    assert m.label({**base, "alpn": "x-amzn-mqtt-ca"})[0] == "aws_iot_mqtt"
    assert m.label({**base, "alpn": "h2,http/1.1"})[0] == "unknown"
    assert m.label({**base, "alpn": None})[0] == "unknown"


def test_conflicting_kb_is_rejected():
    kb = KnowledgeBase.model_validate({"apps": [{"name": "a", "category": "web", "domains": ["x.com"]},
                                                {"name": "b", "category": "web", "domains": ["x.com"]}]})
    with pytest.raises(ValueError, match="x.com"):
        label.Matcher(kb)
    with pytest.raises(ValueError):
        KnowledgeBase.model_validate({"apps": [{"name": "a", "category": "nope"}]})
    with pytest.raises(ValueError):
        KnowledgeBase.model_validate({"apps": [{"name": "a", "category": "web", "ports": ["sctp/1"]}]})


def test_labeled_output(work):
    t = pq.read_table(work / "labeled.parquet")
    assert t.schema.equals(LABELED_SCHEMA)
    rows = t.to_pylist()
    apps = {r["app"] for r in rows}
    assert {"youtube", "wechat", "google_search", "wikipedia", "zoom", "ntp", "dns", "spotify"} <= apps
    assert "unknown" not in apps
    for r in rows:
        assert 0 <= r["label_conf"] <= 1


def test_pfd_export(work):
    doc = json.loads((work / "pfd.json").read_text())
    yt = doc["pfdDatas"]["youtube"]
    assert yt["externalAppId"] == "youtube"
    pfd = yt["pfds"]["youtube-dn"]
    assert "googlevideo.com" in pfd["domainNames"] and "*.googlevideo.com" in pfd["domainNames"]
    assert pfd["dnProtocol"] == "TLS_SNI"
    zoom = doc["pfdDatas"]["zoom"]["pfds"]["zoom-fd"]["flowDescriptions"]
    assert "permit out 17 from any 8801-8810 to assigned" in zoom
