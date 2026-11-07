from upsynth import quic, tls


def test_initial_keys_rfc9001_appendix_a():
    c, s = quic.initial_keys(bytes.fromhex("8394c8f03e515708"))
    assert c.key.hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert c.iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert c.hp.hex() == "9f50449e04a0e810283a1e9933adedd2"
    assert s.key.hex() == "cf3a5331653c364c88f0f379b6067e37"
    assert s.iv.hex() == "0ac1493ca1905853b0bba03e"
    assert s.hp.hex() == "c206b8d9b9f0f37644430b490eeaa314"


def test_initial_roundtrip_and_crypto_reassembly():
    dcid, scid = bytes(range(8)), bytes(range(8, 16))
    ck, sk = quic.initial_keys(dcid)
    ch = tls.build_client_hello(tls.CHROME_QUIC_JA4_R, "quic.example", ["h3"], quic_scid=scid)
    p1 = quic.build_initial(version=quic.V1, dcid=dcid, scid=scid, pn=0, frames=quic.crypto_frame(0, ch[:900]),
                            keys=ck, pad_to=1200)
    p2 = quic.build_initial(version=quic.V1, dcid=dcid, scid=scid, pn=1, frames=quic.crypto_frame(900, ch[900:]),
                            keys=ck, pad_to=1200)
    assert len(p1) == 1200
    pieces = {}
    for p in (p1, p2):
        h = quic.parse_long(p)
        assert h.ptype == "initial" and h.version == quic.V1 and h.dcid == dcid
        for off, data in quic.crypto_frames(h.payload):
            pieces[off] = data
    assert pieces[0] + pieces[900] == ch
    # server Initial: keys from the client's original DCID
    sp = quic.build_initial(version=quic.V1, dcid=scid, scid=b"\xaa" * 8, pn=0,
                            frames=quic.ack_frame(1) + quic.crypto_frame(0, b"\x02\x00\x00\x00"), keys=sk)
    h = quic.parse_long(sp, keys_dcid=dcid, from_client=False)
    assert h.payload is not None


def test_coalesced_handshake_size():
    hs = quic.build_long_opaque(version=quic.V1, ptype="handshake", dcid=b"\x01" * 8, scid=b"\x02" * 8, body=b"\x00" * 50)
    h = quic.parse_long(hs)
    assert h.ptype == "handshake" and h.size == len(hs)
