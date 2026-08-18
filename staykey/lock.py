"""OFFLINE door-lock verifier — the core security component.

A `LockVerifier` is what lives inside a physical door lock. It holds ONLY:
  * the property's Ed25519 PUBLIC key (baked in at install / provisioning), and
  * a periodically-synced revocation list (a set of revoked key-ids).

It makes an unlock/deny decision with NO network and NO database at unlock time.
The unlock protocol is a challenge-response:

  1. `begin_unlock()`      -> lock generates a fresh single-use random challenge.
  2. guest device signs the challenge with its per-key device private key.
  3. `finish_unlock(token, challenge, response, now)` -> Decision.

This module imports ONLY `antireplay`, `credential`, `config`, `errors`,
`cryptography`, and the standard library — proven by tests/test_offline_purity.py.
No DB, no sockets, no web framework. Revocation entries arrive via
`sync_revocations()` (simulating a periodic over-the-air sync), never fetched live.
"""

from __future__ import annotations

from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import config, credential
from .antireplay import ChallengeStatus, ChallengeStore
from .credential import public_from_raw
from .errors import Decision, DenyReason


class LockVerifier:
    """Self-contained offline verifier for a single lock (one property + room)."""

    def __init__(
        self,
        *,
        property_id: str,
        room_id: int,
        property_pub_raw: bytes,
        revoked: Iterable[str] | None = None,
    ) -> None:
        self.property_id = property_id
        self.room_id = int(room_id)
        self._property_pub: Ed25519PublicKey = public_from_raw(property_pub_raw)
        self._revoked: set[str] = set(revoked or ())
        self._challenges = ChallengeStore(
            config.CHALLENGE_TTL_SECONDS, config.CHALLENGE_NONCE_BYTES
        )

    # -- revocation sync (periodic, out of band) ---------------------------
    def sync_revocations(self, revoked: Iterable[str]) -> None:
        """Replace the local revocation snapshot (simulates a periodic OTA sync)."""
        self._revoked = set(revoked)

    @property
    def revoked_snapshot(self) -> frozenset[str]:
        return frozenset(self._revoked)

    # -- challenge-response ------------------------------------------------
    def begin_unlock(self, now: int) -> bytes:
        """Issue a fresh single-use challenge nonce."""
        return self._challenges.issue(int(now))

    def finish_unlock(
        self, *, token: str, challenge: bytes, response: bytes, now: int
    ) -> Decision:
        """Decide unlock/deny using ONLY the local public key + revocation list."""
        now = int(now)

        # 1) Static checks (signature, property, room, window, revocation).
        static = credential.evaluate_static(
            token=token,
            property_pub=self._property_pub,
            expected_property=self.property_id,
            expected_room=self.room_id,
            now=now,
            revoked=self._revoked,
        )
        if static.deny is not None:
            return static.deny
        payload = static.payload
        assert payload is not None
        key_id = str(payload["key_id"])

        # 2) Challenge validity (anti-replay).
        status = self._challenges.check(challenge, now)
        if status is ChallengeStatus.REPLAYED:
            return Decision.deny(DenyReason.REPLAYED, key_id)
        if status is ChallengeStatus.UNKNOWN:
            return Decision.deny(DenyReason.UNKNOWN_CHALLENGE, key_id)

        # 3) Device possession proof (defeats impersonation + replay-with-new-challenge).
        if not credential.verify_device_response(payload["device_pub"], challenge, response):
            # Do NOT consume the challenge: a legit device may retry until TTL.
            return Decision.deny(DenyReason.BAD_RESPONSE, key_id)

        # 4) Success: consume the challenge exactly once.
        self._challenges.consume(challenge, now)
        return Decision.unlock(key_id)
