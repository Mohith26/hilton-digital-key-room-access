"""Challenge-response anti-replay: single-use challenges, replay + expiry."""

from __future__ import annotations

from staykey import config, credential
from staykey.antireplay import ChallengeStatus, ChallengeStore
from tests.conftest import NOW, make_checked_in_stay, present


def test_challenge_is_single_use():
    store = ChallengeStore(ttl_seconds=30, nonce_bytes=8)
    ch = store.issue(NOW)
    assert store.check(ch, NOW) is ChallengeStatus.OK
    store.consume(ch, NOW)
    assert store.check(ch, NOW) is ChallengeStatus.REPLAYED


def test_unknown_and_expired_challenges():
    store = ChallengeStore(ttl_seconds=30, nonce_bytes=8)
    assert store.check(b"never-issued", NOW) is ChallengeStatus.UNKNOWN
    ch = store.issue(NOW)
    assert store.check(ch, NOW + 31) is ChallengeStatus.UNKNOWN  # expired


def test_replay_of_full_presentation_denied(seeded):
    state = seeded
    conn = state.connect()
    _, issued = make_checked_in_stay(state, conn, 101)
    lock = state.lock_for(conn, 101)
    challenge = lock.begin_unlock(NOW)
    response = credential.device_sign(issued.device_sk_b64, challenge)
    first = lock.finish_unlock(token=issued.token, challenge=challenge, response=response, now=NOW)
    assert first.unlocked
    replay = lock.finish_unlock(token=issued.token, challenge=challenge, response=response, now=NOW)
    assert not replay.unlocked and replay.reason.value == "replayed"


def test_unknown_challenge_denied(seeded):
    state = seeded
    conn = state.connect()
    _, issued = make_checked_in_stay(state, conn, 101)
    lock = state.lock_for(conn, 101)
    forged_challenge = b"\x11" * config.CHALLENGE_NONCE_BYTES  # never issued
    response = credential.device_sign(issued.device_sk_b64, forged_challenge)
    dec = lock.finish_unlock(token=issued.token, challenge=forged_challenge, response=response, now=NOW)
    assert not dec.unlocked and dec.reason.value == "unknown_challenge"


def test_bad_response_does_not_consume_challenge(seeded):
    """A wrong device response leaves the challenge usable for a legit retry."""
    state = seeded
    conn = state.connect()
    _, issued = make_checked_in_stay(state, conn, 101)
    lock = state.lock_for(conn, 101)
    challenge = lock.begin_unlock(NOW)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    bad = lock.finish_unlock(token=issued.token, challenge=challenge,
                             response=Ed25519PrivateKey.generate().sign(challenge), now=NOW)
    assert not bad.unlocked and bad.reason.value == "bad_response"
    good = lock.finish_unlock(token=issued.token, challenge=challenge,
                              response=credential.device_sign(issued.device_sk_b64, challenge), now=NOW)
    assert good.unlocked
