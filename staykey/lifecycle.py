"""Key lifecycle: checkout and room-change revoke the affected key(s).

Revocation adds a key-id to the `revocations` table. That table IS the revocation
list synced to locks (`sync_revocations`). A revoked key is denied by the offline
verifier even while still inside its original validity window.

Refresh (routine short-TTL re-fetch) deliberately does NOT revoke: the previous
short-lived key simply lapses at its TTL. Revocation is reserved for lifecycle
events (checkout, room change) — the security-relevant transitions.
"""

from __future__ import annotations

import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import db, keys, reservation
from .credential import IssuedKey
from .errors import NotFoundError, StayKeyError


def refresh_key(conn: sqlite3.Connection, property_sk: Ed25519PrivateKey, stay_id: str, *, now: int) -> IssuedKey:
    """Issue a fresh short-TTL key. The prior key is deactivated (server-side)
    but NOT revoked — it lapses naturally at its TTL (rolling-key model)."""
    stay = db.get_stay(conn, stay_id)
    if stay is None:
        raise NotFoundError(f"stay {stay_id} not found")
    if stay["status"] == "checked_out":
        raise StayKeyError("stay already checked out")
    conn.execute("UPDATE keys SET active=0 WHERE stay_id=? AND active=1", (stay_id,))
    return keys.issue_for_stay(conn, property_sk, stay_id, now=now)


def checkout(conn: sqlite3.Connection, stay_id: str, *, now: int) -> list[str]:
    """Check out: revoke every active key for the stay and free the room.

    Returns the list of revoked key-ids (to sync to the affected lock)."""
    stay = db.get_stay(conn, stay_id)
    if stay is None:
        raise NotFoundError(f"stay {stay_id} not found")

    revoked = db.deactivate_keys_for_stay(conn, stay_id)
    for key_id in revoked:
        db.revoke_key(conn, key_id, now, reason="checkout")
    conn.execute("UPDATE assignments SET active=0 WHERE stay_id=? AND active=1", (stay_id,))
    db.set_stay_status(conn, stay_id, "checked_out")
    return revoked


def change_room(
    conn: sqlite3.Connection,
    property_sk: Ed25519PrivateKey,
    stay_id: str,
    *,
    now: int,
    new_room_id: int | None = None,
) -> tuple[int, list[str], IssuedKey]:
    """Move the stay to a new room: revoke old key(s), reassign, issue a new key.

    Returns (new_room_id, revoked_key_ids, new_issued_key)."""
    stay = db.get_stay(conn, stay_id)
    if stay is None:
        raise NotFoundError(f"stay {stay_id} not found")
    if stay["status"] == "checked_out":
        raise StayKeyError("stay already checked out")

    revoked = db.deactivate_keys_for_stay(conn, stay_id)
    for key_id in revoked:
        db.revoke_key(conn, key_id, now, reason="room_change")

    new_room = reservation.change_room(conn, stay_id, new_room_id=new_room_id)
    issued = keys.issue_for_stay(conn, property_sk, stay_id, now=now)
    return new_room, revoked, issued
