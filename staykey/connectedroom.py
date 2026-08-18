"""Connected Room controls — device commands scoped to the active stay.

`POST /room/{id}/control` (tv/thermostat/lights) is authorized ONLY for:
  * the stay's guest (proven by device challenge-response over the credential),
  * their currently ASSIGNED room (credential room must equal the target room),
  * during the ACTIVE window (checked-in, within validity, not revoked).

Unlike the lock, this authorizer is ONLINE: it consults the DB for the room's
current active assignment, so a key for a checked-out or moved stay (whose key is
revoked and which is no longer the room's active assignment) cannot control the
room. Cross-room commands fail the room match; cross-stay commands fail the
active-assignment check. Together these give 0 cross-scope command acceptance.
"""

from __future__ import annotations

import sqlite3
from typing import Iterable

from . import config, credential, db
from .antireplay import ChallengeStatus, ChallengeStore
from .credential import public_from_raw
from .errors import Decision, DenyReason


class ConnectedRoomAuthorizer:
    def __init__(self, *, property_id: str, property_pub_raw: bytes) -> None:
        self.property_id = property_id
        self._property_pub = public_from_raw(property_pub_raw)
        self._challenges = ChallengeStore(
            config.CHALLENGE_TTL_SECONDS, config.CHALLENGE_NONCE_BYTES
        )

    def begin_command(self, now: int) -> bytes:
        return self._challenges.issue(int(now))

    def authorize(
        self,
        conn: sqlite3.Connection,
        *,
        room_id: int,
        command: str,
        token: str,
        challenge: bytes,
        response: bytes,
        now: int,
    ) -> Decision:
        now = int(now)
        room_id = int(room_id)

        # 0) Command must target a supported device.
        if command not in config.ALLOWED_DEVICES:
            return Decision.deny(DenyReason.BAD_COMMAND)

        # 1) Static credential checks against the TARGET room + live revocations.
        revoked: Iterable[str] = db.revocation_list(conn)
        static = credential.evaluate_static(
            token=token,
            property_pub=self._property_pub,
            expected_property=self.property_id,
            expected_room=room_id,
            now=now,
            revoked=set(revoked),
        )
        if static.deny is not None:
            return static.deny
        payload = static.payload
        assert payload is not None
        key_id = str(payload["key_id"])

        # 2) The credential's stay must be the room's ACTIVE, checked-in stay.
        assignment = db.active_assignment_for_room(conn, room_id)
        stay = db.get_stay(conn, str(payload["stay_id"]))
        if (
            assignment is None
            or assignment["stay_id"] != payload["stay_id"]
            or stay is None
            or stay["status"] != "checked_in"
            or int(stay["room_id"]) != room_id
        ):
            return Decision.deny(DenyReason.NOT_ACTIVE_STAY, key_id)

        # 3) Device possession proof + anti-replay (same primitive as the lock).
        status = self._challenges.check(challenge, now)
        if status is ChallengeStatus.REPLAYED:
            return Decision.deny(DenyReason.REPLAYED, key_id)
        if status is ChallengeStatus.UNKNOWN:
            return Decision.deny(DenyReason.UNKNOWN_CHALLENGE, key_id)
        if not credential.verify_device_response(payload["device_pub"], challenge, response):
            return Decision.deny(DenyReason.BAD_RESPONSE, key_id)

        self._challenges.consume(challenge, now)
        return Decision.allow(key_id)
