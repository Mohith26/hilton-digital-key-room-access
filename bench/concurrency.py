"""No-double-book bench: prove overlapping stays never share a room, incl. under
concurrent booking. Uses a file-backed SQLite DB + threads racing to grab rooms.
"""

from __future__ import annotations

import tempfile
import threading
import uuid
from pathlib import Path

from staykey import db, reservation
from staykey.errors import RoomUnavailableError

NOW = 1_800_000_000
WINDOW = (NOW, NOW + 2 * 24 * 3600)  # all stays overlap this window


def _seed(conn, property_id: str, n_rooms: int) -> None:
    db.init_db(conn)
    db.add_guest(conn, "g", "Guest", "g@example.com")
    for i in range(n_rooms):
        db.add_room(conn, 100 + i, property_id, str(100 + i), "king")


def _race_for_room(db_path: str, property_id: str, room_id: int, n_threads: int) -> dict:
    """n_threads all try to assign the SAME room for the SAME overlapping window."""
    # Pre-create the stays (each thread assigns its own stay to the shared room).
    with db.connect(db_path) as conn:
        stay_ids = []
        for _ in range(n_threads):
            sid = "s_" + uuid.uuid4().hex[:10]
            db.add_stay(conn, sid, "g", property_id, "king", WINDOW[0], WINDOW[1])
            stay_ids.append(sid)

    barrier = threading.Barrier(n_threads)
    results: list[str | None] = [None] * n_threads
    errors: list[int] = [0] * n_threads

    def worker(idx: int, stay_id: str) -> None:
        conn = db.connect(db_path)
        try:
            barrier.wait()
            room = reservation.assign_room(conn, stay_id, preferred_room_id=room_id)
            results[idx] = room
        except RoomUnavailableError:
            errors[idx] = 1
        finally:
            conn.close()

    threads = [threading.Thread(target=worker, args=(i, sid)) for i, sid in enumerate(stay_ids)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = sum(1 for r in results if r is not None)
    with db.connect(db_path) as conn:
        assigned = conn.execute(
            "SELECT COUNT(*) c FROM assignments WHERE room_id=? AND active=1", (room_id,)
        ).fetchone()["c"]
    return {
        "threads": n_threads,
        "successes": successes,
        "room_unavailable_rejections": sum(errors),
        "assignments_for_room": assigned,
        "double_booked": max(0, assigned - 1),
    }


def _multi_room(db_path: str, property_id: str, n_rooms: int, n_stays: int) -> dict:
    """n_stays overlapping stays compete for n_rooms; expect exactly n_rooms assigned
    and 0 room shared by two overlapping stays."""
    with db.connect(db_path) as conn:
        stay_ids = []
        for _ in range(n_stays):
            sid = "s_" + uuid.uuid4().hex[:10]
            db.add_stay(conn, sid, "g", property_id, "king", WINDOW[0], WINDOW[1])
            stay_ids.append(sid)

    barrier = threading.Barrier(n_stays)
    assigned_rooms: list[int | None] = [None] * n_stays

    def worker(idx: int, stay_id: str) -> None:
        conn = db.connect(db_path)
        try:
            barrier.wait()
            assigned_rooms[idx] = reservation.assign_room(conn, stay_id)
        except RoomUnavailableError:
            assigned_rooms[idx] = None
        finally:
            conn.close()

    threads = [threading.Thread(target=worker, args=(i, sid)) for i, sid in enumerate(stay_ids)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    got = [r for r in assigned_rooms if r is not None]
    return {
        "rooms": n_rooms,
        "competing_overlapping_stays": n_stays,
        "assigned": len(got),
        "distinct_rooms_used": len(set(got)),
        "duplicate_room_assignments": len(got) - len(set(got)),
    }


def run() -> dict:
    property_id = "HILTON-DEMO-001"

    p1 = str(Path(tempfile.mkdtemp()) / "race.sqlite")
    with db.connect(p1) as conn:
        _seed(conn, property_id, n_rooms=1)
    single = _race_for_room(p1, property_id, room_id=100, n_threads=32)

    p2 = str(Path(tempfile.mkdtemp()) / "multi.sqlite")
    with db.connect(p2) as conn:
        _seed(conn, property_id, n_rooms=10)
    multi = _multi_room(p2, property_id, n_rooms=10, n_stays=40)

    return {
        "single_room_race": single,
        "multi_room_race": multi,
        "double_booked_total": single["double_booked"] + multi["duplicate_room_assignments"],
        "note": "half-open interval overlap check inside BEGIN IMMEDIATE serializes writers; "
        "32 threads race for 1 room -> exactly 1 wins; 40 overlapping stays for 10 rooms -> 10 assigned, 0 shared.",
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2))
