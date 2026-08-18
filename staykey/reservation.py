"""Overlap-safe room assignment — the "no double-booking" guarantee.

Two stays overlap iff their half-open intervals [check_in, check_out) intersect:
    overlap  <=>  a.check_in < b.check_out AND b.check_in < a.check_out

A room is never assigned to two overlapping stays. The check-and-insert runs
inside a `BEGIN IMMEDIATE` transaction so concurrent writers serialize: SQLite
grants the write lock to one transaction at a time, and each transaction sees the
committed state of prior ones, so exactly one of several racing assignments to
the same room+window can win.
"""

from __future__ import annotations

import sqlite3

from . import db
from .errors import NotFoundError, RoomUnavailableError


def _has_overlap(conn: sqlite3.Connection, room_id: int, check_in: int, check_out: int) -> bool:
    row = conn.execute(
        """
        SELECT 1 FROM assignments
        WHERE room_id = ? AND active = 1
          AND check_in < ? AND ? < check_out
        LIMIT 1
        """,
        (room_id, int(check_out), int(check_in)),
    ).fetchone()
    return row is not None


def _candidate_rooms(conn: sqlite3.Connection, property_id: str, room_type: str) -> list[int]:
    rows = conn.execute(
        "SELECT room_id FROM rooms WHERE property_id=? AND room_type=? ORDER BY room_id",
        (property_id, room_type),
    ).fetchall()
    return [r["room_id"] for r in rows]


def assign_room(conn: sqlite3.Connection, stay_id: str, *, preferred_room_id: int | None = None) -> int:
    """Assign a non-overlapping room to `stay_id`. Returns the room_id.

    Raises RoomUnavailableError if no room of the requested type is free for the
    stay's window (or the preferred room, if given, is not free).
    """
    stay = db.get_stay(conn, stay_id)
    if stay is None:
        raise NotFoundError(f"stay {stay_id} not found")
    if stay["room_id"] is not None:
        return int(stay["room_id"])

    check_in, check_out = int(stay["check_in"]), int(stay["check_out"])
    property_id, room_type = stay["property_id"], stay["room_type"]

    try:
        conn.execute("BEGIN IMMEDIATE")
        if preferred_room_id is not None:
            room = db.get_room(conn, preferred_room_id)
            if room is None or room["property_id"] != property_id:
                raise RoomUnavailableError(f"room {preferred_room_id} not in property {property_id}")
            candidates = [int(preferred_room_id)]
        else:
            candidates = _candidate_rooms(conn, property_id, room_type)

        chosen: int | None = None
        for room_id in candidates:
            if not _has_overlap(conn, room_id, check_in, check_out):
                chosen = room_id
                break
        if chosen is None:
            raise RoomUnavailableError(
                f"no {room_type} room free in {property_id} for [{check_in},{check_out})"
            )

        conn.execute(
            "INSERT INTO assignments(room_id, stay_id, check_in, check_out, active) VALUES (?,?,?,?,1)",
            (chosen, stay_id, check_in, check_out),
        )
        db.set_stay_room(conn, stay_id, chosen)
        conn.execute("COMMIT")
        return chosen
    except Exception:
        conn.execute("ROLLBACK")
        raise


def change_room(conn: sqlite3.Connection, stay_id: str, *, new_room_id: int | None = None) -> int:
    """Move a stay to a different (non-overlapping) room. Returns the new room_id.

    Deactivates the old assignment so it no longer blocks, then assigns a new one
    within the same window. The caller (lifecycle) revokes the old key.
    """
    stay = db.get_stay(conn, stay_id)
    if stay is None:
        raise NotFoundError(f"stay {stay_id} not found")
    old_room = stay["room_id"]
    check_in, check_out = int(stay["check_in"]), int(stay["check_out"])
    property_id, room_type = stay["property_id"], stay["room_type"]

    try:
        conn.execute("BEGIN IMMEDIATE")
        # Retire the current assignment first.
        conn.execute(
            "UPDATE assignments SET active=0 WHERE stay_id=? AND active=1", (stay_id,)
        )
        if new_room_id is not None:
            room = db.get_room(conn, new_room_id)
            if room is None or room["property_id"] != property_id:
                raise RoomUnavailableError(f"room {new_room_id} not in property {property_id}")
            candidates = [int(new_room_id)]
        else:
            candidates = [r for r in _candidate_rooms(conn, property_id, room_type) if r != old_room]

        chosen: int | None = None
        for room_id in candidates:
            if not _has_overlap(conn, room_id, check_in, check_out):
                chosen = room_id
                break
        if chosen is None:
            # Nothing free: restore the old assignment and fail.
            conn.execute(
                "UPDATE assignments SET active=1 WHERE stay_id=? AND room_id=?",
                (stay_id, old_room),
            )
            raise RoomUnavailableError(f"no alternate {room_type} room free in {property_id}")

        conn.execute(
            "INSERT INTO assignments(room_id, stay_id, check_in, check_out, active) VALUES (?,?,?,?,1)",
            (chosen, stay_id, check_in, check_out),
        )
        db.set_stay_room(conn, stay_id, chosen)
        conn.execute("COMMIT")
        return chosen
    except Exception:
        conn.execute("ROLLBACK")
        raise
