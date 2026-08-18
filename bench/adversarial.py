"""Adversarial + legitimate key generator for the headline security suite.

Builds a deterministic (seeded) set of key *presentations* against a single
offline lock (property HILTON-DEMO-001, room 101). Each `Attempt` runs the full
challenge-response dance against the lock and yields a Decision. Adversarial
attempts MUST be denied (0 unauthorized unlocks); legitimate in-window keys MUST
unlock.

Categories: expired, not_yet_valid, wrong_room, wrong_property, forged_signature,
tampered_payload, revoked, replayed, impersonation (stolen token, no device key),
malformed.
"""

from __future__ import annotations

import base64
import random
from dataclasses import dataclass, field
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from staykey import config, credential
from staykey.credential import IssuedKey, canonical_bytes
from staykey.errors import Decision
from staykey.lock import LockVerifier

PROPERTY_ID = "HILTON-DEMO-001"
OTHER_PROPERTY_ID = "MARRIOTT-OTHER-999"
TARGET_ROOM = 101
NOW = 1_800_000_000  # fixed reference epoch for determinism


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@dataclass
class Scenario:
    property_sk: Ed25519PrivateKey
    property_pub_raw: bytes
    attacker_sk: Ed25519PrivateKey
    revoked_ids: set[str] = field(default_factory=set)


def build_scenario() -> Scenario:
    property_sk = Ed25519PrivateKey.generate()
    return Scenario(
        property_sk=property_sk,
        property_pub_raw=credential.public_raw(property_sk.public_key()),
        attacker_sk=Ed25519PrivateKey.generate(),
    )


def make_lock(scn: Scenario) -> LockVerifier:
    return LockVerifier(
        property_id=PROPERTY_ID,
        room_id=TARGET_ROOM,
        property_pub_raw=scn.property_pub_raw,
        revoked=set(scn.revoked_ids),
    )


def _issue(scn: Scenario, *, room_ids, valid_from, valid_until, property_id=PROPERTY_ID,
           signer: Ed25519PrivateKey | None = None) -> IssuedKey:
    return credential.issue_credential(
        property_sk=signer or scn.property_sk,
        guest_id="g_demo",
        stay_id="s_demo",
        property_id=property_id,
        room_ids=room_ids,
        valid_from=valid_from,
        valid_until=valid_until,
        issued_at=valid_from,
    )


@dataclass
class Attempt:
    category: str
    expect_unlock: bool
    run: Callable[[LockVerifier], Decision]


def _present(lock: LockVerifier, token: str, device_sk_b64: str | None, now: int,
             *, wrong_device: bool = False) -> Decision:
    """Full presentation: get a fresh challenge, sign it, finish the unlock."""
    challenge = lock.begin_unlock(now)
    if device_sk_b64 is None:
        response = b"\x00" * 64  # malformed/absent response
    elif wrong_device:
        response = Ed25519PrivateKey.generate().sign(challenge)  # attacker without device key
    else:
        response = credential.device_sign(device_sk_b64, challenge)
    return lock.finish_unlock(token=token, challenge=challenge, response=response, now=now)


def build_attempts(scn: Scenario, *, n_each: int = 30, n_legit: int = 60, seed: int = config.RANDOM_SEED) -> list[Attempt]:
    rng = random.Random(seed)
    attempts: list[Attempt] = []

    # -- legitimate positives -------------------------------------------
    for _ in range(n_legit):
        span = rng.randint(1800, 7200)
        key = _issue(scn, room_ids=[TARGET_ROOM], valid_from=NOW - span, valid_until=NOW + span)
        attempts.append(Attempt("legit", True, lambda lk, k=key: _present(lk, k.token, k.device_sk_b64, NOW)))

    # -- expired ---------------------------------------------------------
    for _ in range(n_each):
        off = rng.randint(60, 100000)
        key = _issue(scn, room_ids=[TARGET_ROOM], valid_from=NOW - 2 * off, valid_until=NOW - off)
        attempts.append(Attempt("expired", False, lambda lk, k=key: _present(lk, k.token, k.device_sk_b64, NOW)))

    # -- not-yet-valid (before check-in) ---------------------------------
    for _ in range(n_each):
        off = rng.randint(60, 100000)
        key = _issue(scn, room_ids=[TARGET_ROOM], valid_from=NOW + off, valid_until=NOW + 2 * off)
        attempts.append(Attempt("not_yet_valid", False, lambda lk, k=key: _present(lk, k.token, k.device_sk_b64, NOW)))

    # -- wrong room ------------------------------------------------------
    for _ in range(n_each):
        other = rng.choice([102, 103, 205, 999])
        key = _issue(scn, room_ids=[other], valid_from=NOW - 3600, valid_until=NOW + 3600)
        attempts.append(Attempt("wrong_room", False, lambda lk, k=key: _present(lk, k.token, k.device_sk_b64, NOW)))

    # -- wrong property (real signer, wrong property_id) -----------------
    for _ in range(n_each):
        key = _issue(scn, room_ids=[TARGET_ROOM], valid_from=NOW - 3600, valid_until=NOW + 3600,
                     property_id=OTHER_PROPERTY_ID)
        attempts.append(Attempt("wrong_property", False, lambda lk, k=key: _present(lk, k.token, k.device_sk_b64, NOW)))

    # -- forged signature (attacker key signs a valid-looking payload) ---
    for _ in range(n_each):
        key = _issue(scn, room_ids=[TARGET_ROOM], valid_from=NOW - 3600, valid_until=NOW + 3600,
                     signer=scn.attacker_sk)
        attempts.append(Attempt("forged_signature", False, lambda lk, k=key: _present(lk, k.token, k.device_sk_b64, NOW)))

    # -- tampered payload (flip the window/room, keep original signature) -
    for _ in range(n_each):
        key = _issue(scn, room_ids=[TARGET_ROOM], valid_from=NOW - 3600, valid_until=NOW + 3600)
        payload = dict(key.payload)
        payload["valid_until"] = NOW + 10_000_000  # attacker extends validity
        tampered = f"{_b64u(canonical_bytes(payload))}.{key.token.split('.')[1]}"
        attempts.append(Attempt("tampered_payload", False, lambda lk, t=tampered, k=key: _present(lk, t, k.device_sk_b64, NOW)))

    # -- revoked (valid key whose id the lock has on its revocation list) -
    for _ in range(n_each):
        key = _issue(scn, room_ids=[TARGET_ROOM], valid_from=NOW - 3600, valid_until=NOW + 3600)
        scn.revoked_ids.add(key.key_id)  # lock must be rebuilt after this via make_lock
        attempts.append(Attempt("revoked", False, lambda lk, k=key: _present(lk, k.token, k.device_sk_b64, NOW)))

    # -- replayed (capture a valid presentation, resend the same challenge) -
    for _ in range(n_each):
        key = _issue(scn, room_ids=[TARGET_ROOM], valid_from=NOW - 3600, valid_until=NOW + 3600)
        attempts.append(Attempt("replayed", False, lambda lk, k=key: _replay(lk, k)))

    # -- impersonation (stolen token, attacker lacks the device key) -----
    for _ in range(n_each):
        key = _issue(scn, room_ids=[TARGET_ROOM], valid_from=NOW - 3600, valid_until=NOW + 3600)
        attempts.append(Attempt("impersonation", False, lambda lk, k=key: _present(lk, k.token, k.device_sk_b64, NOW, wrong_device=True)))

    # -- malformed token -------------------------------------------------
    garbage = ["not-a-token", "", "....", "aGVsbG8.d29ybGQ", "%%%.$$$"]
    for i in range(n_each):
        tok = garbage[i % len(garbage)]
        attempts.append(Attempt("malformed", False, lambda lk, t=tok: _present(lk, t, None, NOW)))

    return attempts


def _replay(lock: LockVerifier, key: IssuedKey) -> Decision:
    """First present succeeds (consumes the challenge); the replay is the attack."""
    challenge = lock.begin_unlock(NOW)
    response = credential.device_sign(key.device_sk_b64, challenge)
    first = lock.finish_unlock(token=key.token, challenge=challenge, response=response, now=NOW)
    assert first.unlocked, "replay setup must first legitimately unlock"
    # The adversarial event: resend the identical (challenge, response).
    return lock.finish_unlock(token=key.token, challenge=challenge, response=response, now=NOW)
