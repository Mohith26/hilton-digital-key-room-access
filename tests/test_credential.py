"""Unit tests for the pure credential core: parse, tamper, forge, device sig."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from staykey import credential
from staykey.credential import canonical_bytes, evaluate_static, parse_token

NOW = 1_800_000_000


def _issue(sk, **over):
    base = dict(guest_id="g", stay_id="s", property_id="P", room_ids=[101],
                valid_from=NOW - 10, valid_until=NOW + 10, issued_at=NOW - 10)
    base.update(over)
    return credential.issue_credential(property_sk=sk, **base)


def test_roundtrip_valid():
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key()
    issued = _issue(sk)
    res = evaluate_static(token=issued.token, property_pub=pub, expected_property="P",
                          expected_room=101, now=NOW, revoked=set())
    assert res.deny is None and res.payload["key_id"] == issued.key_id


def test_tampered_payload_fails_signature():
    sk = Ed25519PrivateKey.generate()
    issued = _issue(sk)
    payload = dict(issued.payload)
    payload["valid_until"] = NOW + 10_000_000
    from staykey.credential import _b64u_encode

    tampered = f"{_b64u_encode(canonical_bytes(payload))}.{issued.token.split('.')[1]}"
    res = evaluate_static(token=tampered, property_pub=sk.public_key(), expected_property="P",
                          expected_room=101, now=NOW, revoked=set())
    assert res.deny is not None and res.deny.reason.value == "forged_signature"


def test_forged_signature_denied():
    real = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    issued = _issue(attacker)  # signed by attacker, verified with real pub
    res = evaluate_static(token=issued.token, property_pub=real.public_key(), expected_property="P",
                          expected_room=101, now=NOW, revoked=set())
    assert res.deny is not None and res.deny.reason.value == "forged_signature"


def test_malformed_token():
    sk = Ed25519PrivateKey.generate()
    for bad in ("garbage", "", "a.b.c", "%%%.$$$"):
        res = evaluate_static(token=bad, property_pub=sk.public_key(), expected_property="P",
                              expected_room=101, now=NOW, revoked=set())
        assert res.deny is not None and res.deny.reason.value == "malformed"


def test_device_signature_verify():
    sk = Ed25519PrivateKey.generate()
    issued = _issue(sk)
    challenge = credential.new_challenge()
    good = credential.device_sign(issued.device_sk_b64, challenge)
    assert credential.verify_device_response(issued.payload["device_pub"], challenge, good)
    other = Ed25519PrivateKey.generate().sign(challenge)
    assert not credential.verify_device_response(issued.payload["device_pub"], challenge, other)


def test_parse_token_none_on_bad_input():
    assert parse_token("nodot") is None
    assert parse_token("a.b.c") is None
