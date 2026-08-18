"""Pure single-use challenge store for challenge-response anti-replay.

Shared by the offline lock and the connected-room authorizer. A challenge is a
fresh random nonce, valid only until `ttl` seconds pass, and usable exactly once.
Replaying a previously-consumed challenge is distinguishable (REPLAYED) from one
that was never issued or has expired (UNKNOWN).

Pure stdlib only — safe to embed inside the offline lock.
"""

from __future__ import annotations

import os
from enum import Enum


class ChallengeStatus(str, Enum):
    OK = "ok"
    UNKNOWN = "unknown"    # never issued, or expired
    REPLAYED = "replayed"  # already consumed


class ChallengeStore:
    def __init__(self, ttl_seconds: int, nonce_bytes: int = 32) -> None:
        self._ttl = int(ttl_seconds)
        self._nonce_bytes = int(nonce_bytes)
        self._pending: dict[bytes, int] = {}   # challenge -> issued_at
        self._consumed: dict[bytes, int] = {}  # challenge -> consumed_at

    def issue(self, now: int) -> bytes:
        self._gc(now)
        challenge = os.urandom(self._nonce_bytes)
        self._pending[challenge] = int(now)
        return challenge

    def check(self, challenge: bytes, now: int) -> ChallengeStatus:
        """Non-consuming status check."""
        if challenge in self._consumed:
            return ChallengeStatus.REPLAYED
        issued_at = self._pending.get(challenge)
        if issued_at is None:
            return ChallengeStatus.UNKNOWN
        if int(now) - issued_at > self._ttl:
            return ChallengeStatus.UNKNOWN
        return ChallengeStatus.OK

    def consume(self, challenge: bytes, now: int) -> None:
        self._pending.pop(challenge, None)
        self._consumed[challenge] = int(now)

    def _gc(self, now: int) -> None:
        now = int(now)
        for c in [c for c, t in self._pending.items() if now - t > self._ttl]:
            self._pending.pop(c, None)
        for c in [c for c, t in self._consumed.items() if now - t > self._ttl * 4]:
            self._consumed.pop(c, None)
