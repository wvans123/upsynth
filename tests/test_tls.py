import os

from upsynth import tls

CHROME_DOC_JA4_R = (
    "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_"
    "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
)


def test_ja4_matches_foxio_example():
    # the example in the FoxIO JA4 specification
    assert tls.ja4_from_raw(CHROME_DOC_JA4_R) == "t13d1516h2_8daaf6152771_e5627efa2ab1"


def test_built_hello_has_the_requested_fingerprint():
    for raw, alpn in ((CHROME_DOC_JA4_R, ["h2", "http/1.1"]), (tls.CHROME_JA4_R, ["h2", "http/1.1"])):
        msg = tls.build_client_hello(raw, "www.example.org", alpn, rnd=os.urandom)
        ch = tls.parse_client_hello(msg)
        assert ch.sni == "www.example.org"
        assert ch.alpn == alpn
        j, r = tls.ja4(ch, "t")
        assert r == raw
        assert j == tls.ja4_from_raw(raw)


def test_quic_hello_fingerprint_and_transport_params():
    scid = b"\x01" * 8
    msg = tls.build_client_hello(tls.CHROME_QUIC_JA4_R, "video.example", ["h3"], quic_scid=scid)
    ch = tls.parse_client_hello(msg)
    assert tls.EXT_QUIC_TP in ch.extensions
    assert tls.ja4(ch, "q")[0] == tls.ja4_from_raw(tls.CHROME_QUIC_JA4_R)
    assert msg[4 + 2 + 32] == 0  # QUIC: empty legacy_session_id


def test_bundled_stacks_are_consistent():
    from upsynth.sample import OKHTTP_JA4_R, SAFARI_JA4_R

    for raw in (tls.CHROME_JA4_R, tls.CHROME_QUIC_JA4_R, SAFARI_JA4_R, OKHTTP_JA4_R):
        assert tls.normalize_raw(raw) == raw


def test_grease_is_ignored():
    msg = tls.build_client_hello(CHROME_DOC_JA4_R, "a.example", ["h2"])
    ch = tls.parse_client_hello(msg)
    ch.ciphers.insert(0, 0x0A0A)
    ch.extensions.insert(0, 0x1A1A)
    assert tls.ja4(ch, "t")[0] == tls.ja4_from_raw(CHROME_DOC_JA4_R)


def test_hello_split_across_records():
    msg = tls.build_client_hello(tls.CHROME_JA4_R, "split.example", ["h2"])
    stream = tls.record(22, msg[:100], 0x0301) + tls.record(22, msg[100:], 0x0301)
    assert tls.handshake_from_records(stream) == msg
    assert tls.handshake_from_records(stream[:50]) is None


def test_alpn_non_alnum_uses_hex():
    ch = tls.ClientHello(0x0303, [0x1301], [0x0010], alpn=["\x01x\x02"])
    assert tls.ja4(ch, "t")[0][8:10] == "02"
