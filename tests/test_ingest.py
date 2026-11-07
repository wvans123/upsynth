import ipaddress
import subprocess

import pyarrow.parquet as pq

from upsynth import ingest
from upsynth.anon import Anonymizer
from upsynth.asn import AsnDB
from upsynth.schemas import FLOW_SCHEMA, SEQ_LEN

from .conftest import KEY


def test_flows_schema_and_counts(work):
    t = pq.read_table(work / "flows.parquet")
    assert t.schema.equals(FLOW_SCHEMA)
    rows = t.to_pylist()
    assert len(rows) == 106  # 58 app flows + 48 DNS lookups
    assert all(r["iface"] == "n3" for r in rows)
    assert all(len(r["seq_len"]) <= SEQ_LEN and len(r["seq_len"]) == len(r["seq_iat"]) for r in rows)
    assert all(r["seq_iat"][0] == 0 for r in rows)
    tls_rows = [r for r in rows if r["sni"]]
    assert len(tls_rows) == 43
    assert {r["quic_version"] for r in rows if r["quic_version"]} == {"0x00000001"}
    assert all(r["ja4"].startswith("q13") for r in rows if r["quic_version"])
    assert any(r["http_host"] == "connectivitycheck.gstatic.com" for r in rows)


def test_gtpu_fields_kept_as_tokens(work):
    rows = pq.read_table(work / "flows.parquet").to_pylist()
    a = Anonymizer(KEY)
    assert {r["teid_ul"] for r in rows} <= {a.teid(0x100 + i) for i in range(3)}
    assert {r["teid_dl"] for r in rows} <= {a.teid(0x200 + i) for i in range(3)}
    assert {r["qfi"] for r in rows} == {1, 9}
    # first packet of a TCP flow is the uplink SYN
    tcp = [r for r in rows if r["proto"] == 6]
    assert all(r["seq_len"][0] > 0 for r in tcp)


def test_no_raw_addresses_or_payload(work):
    raw = (work / "flows.parquet").read_bytes()
    for ip in ("10.45.0.2", "10.45.0.3", "8.8.8.8", "198.18."):
        assert ip.encode() not in raw
    rows = pq.read_table(work / "flows.parquet").to_pylist()
    ue_tokens = {r["ue"] for r in rows}
    assert Anonymizer(KEY).ip(ipaddress.ip_address("10.45.0.2").packed) in ue_tokens
    assert all(len(t) == 16 for t in ue_tokens)


def test_dns_name_needs_same_ue_and_window():
    c = ingest.DnsCache(window=10)
    ue1, ue2, srv = b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", b"\xc6\x12\x00\x01"
    c.add(ue1, srv, "a.example", 100.0)
    assert c.get(ue1, srv, 105.0) == "a.example"
    assert c.get(ue2, srv, 105.0) is None
    assert c.get(ue1, srv, 111.0) is None


def test_n6_capture(work, tmp_path):
    res = ingest.run(work / "sample_n6.pcap", tmp_path / "f.parquet", key=KEY)
    assert res["flows"] == 106 and res["flows_n6"] == 106 and res["gtpu_packets"] == 0


def test_udp_idle_timeout_splits(work, tmp_path):
    # the RTP-like call has 8-12 ms gaps; a 1 ms idle timeout cuts every packet into its own flow
    a = ingest.run(work / "sample_n3.pcap", tmp_path / "a.parquet", key=KEY)
    b = ingest.run(work / "sample_n3.pcap", tmp_path / "b.parquet", key=KEY, udp_idle=0.001)
    assert b["flows"] > a["flows"] + 1000


def test_asn_lookup(tmp_path):
    p = tmp_path / "ip2asn.tsv"
    p.write_text("198.18.0.0\t198.19.255.255\t64500\tZZ\tTEST\n8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n")
    db = AsnDB.load(p)
    assert db.lookup(ipaddress.ip_address("198.18.3.4").packed) == 64500
    assert db.lookup(ipaddress.ip_address("8.8.8.8").packed) == 15169
    assert db.lookup(ipaddress.ip_address("1.1.1.1").packed) is None
    q = tmp_path / "ipasn.dat"
    q.write_text("; comment\n198.18.0.0/15\t64500\n198.18.1.0/24\t64501\n")
    db = AsnDB.load(q)
    assert db.lookup(ipaddress.ip_address("198.18.1.9").packed) == 64501
    assert db.lookup(ipaddress.ip_address("198.18.2.9").packed) == 64500


def test_asn_column_filled(work, tmp_path):
    p = tmp_path / "asn.tsv"
    p.write_text("198.18.0.0\t198.19.255.255\t64500\tZZ\tTEST\n")
    ingest.run(work / "sample_n3.pcap", tmp_path / "f.parquet", key=KEY, asn_db=p)
    rows = pq.read_table(tmp_path / "f.parquet").to_pylist()
    assert {r["asn"] for r in rows if r["server_port"] != 53} == {64500}


def test_reconciles_with_tshark(work, tshark):
    """Same SNIs and the same number of TCP conversations as tshark sees."""
    out = subprocess.run([tshark, "-n", "-r", str(work / "sample_n3.pcap"), "-Y", "tls.handshake.type == 1 || quic",
                          "-T", "fields", "-e", "tls.handshake.extensions_server_name"],
                         capture_output=True, text=True, check=True).stdout
    tshark_snis = {s for s in out.split() if s}
    rows = pq.read_table(work / "flows.parquet").to_pylist()
    assert {r["sni"] for r in rows if r["sni"]} == tshark_snis
    conv = subprocess.run([tshark, "-n", "-q", "-r", str(work / "sample_n3.pcap"), "-z", "conv,tcp"],
                          capture_output=True, text=True, check=True).stdout
    n_conv = sum(1 for line in conv.splitlines() if "<->" in line)
    assert n_conv == sum(1 for r in rows if r["proto"] == 6)
