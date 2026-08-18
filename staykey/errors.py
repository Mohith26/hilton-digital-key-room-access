"""Decision reasons and domain exceptions.

`DenyReason` enumerates every way a presented key can be rejected. The verifier
never returns a bare boolean; it returns a `Decision` carrying the reason, so
tests and audit logs can assert *why* something was denied.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DenyReason(str, Enum):
    FORGED_SIGNATURE = "forged_signature"        # property signature invalid
    TAMPERED_PAYLOAD = "tampered_payload"        # payload mutated after signing
    WRONG_PROPERTY = "wrong_property"            # key not for this property
    WRONG_ROOM = "wrong_room"                    # key not for this room
    NOT_YET_VALID = "not_yet_valid"              # now < valid_from (before check-in)
    EXPIRED = "expired"                          # now > valid_until
    REVOKED = "revoked"                          # key-id on the revocation list
    UNKNOWN_CHALLENGE = "unknown_challenge"      # challenge not issued / expired
    REPLAYED = "replayed"                        # challenge already consumed
    BAD_RESPONSE = "bad_response"                # device signature over challenge invalid
    MALFORMED = "malformed"                      # token could not be parsed
    NOT_ACTIVE_STAY = "not_active_stay"          # credential is not the room's active checked-in stay
    BAD_COMMAND = "bad_command"                  # unsupported connected-room device/command


class UnlockOutcome(str, Enum):
    UNLOCK = "unlock"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    """Immutable verifier decision."""

    outcome: UnlockOutcome
    reason: DenyReason | None = None
    key_id: str | None = None

    @property
    def unlocked(self) -> bool:
        return self.outcome is UnlockOutcome.UNLOCK

    @property
    def allowed(self) -> bool:
        """Alias for connected-room authorization (UNLOCK == command allowed)."""
        return self.outcome is UnlockOutcome.UNLOCK

    @staticmethod
    def unlock(key_id: str) -> "Decision":
        return Decision(UnlockOutcome.UNLOCK, None, key_id)

    # `allow` is the same positive outcome, named for the connected-room path.
    allow = unlock

    @staticmethod
    def deny(reason: DenyReason, key_id: str | None = None) -> "Decision":
        return Decision(UnlockOutcome.DENY, reason, key_id)


class StayKeyError(Exception):
    """Base domain error."""


class RoomUnavailableError(StayKeyError):
    """No room could be assigned without an overlap (would double-book)."""


class NotFoundError(StayKeyError):
    """Referenced entity does not exist."""


class ValidationError(StayKeyError):
    """Invalid input at a system boundary."""
