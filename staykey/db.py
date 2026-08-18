"""SQLite reservation store: schema, connections, and low-level row access.

Times are epoch seconds (UTC, integer). Stays use half-open intervals
[check_in, check_out). WAL + `busy_timeout` + `BEGIN IMMEDIATE` (in
reservation.py) give correct writer serialization for the concurrency test.

No secret is ever stored here: the guest's device PRIVATE key is returned to the
phone at issuance and never persisted. The `keys` table stores only the public
token (which contains the device PUBLIC key).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS guests (
    guest_id   TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    email      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rooms (
    room_id     INTEGER PRIMARY KEY,
    property_id TEXT NOT NULL,
    number      TEXT NOT NULL,
    room_type   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS stays (
    stay_id     TEXT PRIMARY KEY,
    guest_id    TEXT NOT NULL REFERENCES guests(guest_id),
    property_id TEXT NOT NULL,
    room_type   TEXT NOT NULL,
    room_id     INTEGER REFERENCES rooms(room_id),
    check_in    INTEGER NOT NULL,
    check_out   INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'reserved'   -- reserved | checked_in | checked_out
);
CREATE TABLE IF NOT EXISTS assignments (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id   INTEGER NOT NULL REFERENCES rooms(room_id),
    stay_id   TEXT NOT NULL REFERENCES stays(stay_id),
    check_in  INTEGER NOT NULL,
    check_out INTEGER NOT NULL,
    active    INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_assign_room ON assignments(room_id, active);
CREATE TABLE IF NOT EXISTS keys (
    key_id      TEXT PRIMARY KEY,
    stay_id     TEXT NOT NULL REFERENCES stays(stay_id),
    room_id     INTEGER NOT NULL,
    issued_at   INTEGER NOT NULL,
    valid_from  INTEGER NOT NULL,
    valid_until INTEGER NOT NULL,
    token       TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_keys_stay ON keys(stay_id, active);
CREATE TABLE IF NOT EXISTS revocations (
    key_id     TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL,
    reason     TEXT NOT NULL
);
"""


def connect(path: Path | str | None = None) -> sqlite3.Connection:
    """Open a connection with WAL + busy_timeout for correct concurrent writers."""
    db_path = str(path or config.DB_PATH)
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


# --------------------------------------------------------------------------
# Row helpers (small, explicit; no ORM)
# --------------------------------------------------------------------------
def add_guest(conn: sqlite3.Connection, guest_id: str, name: str, email: str) -> None:
    conn.execute(
        "INSERT INTO guests(guest_id, name, email) VALUES (?,?,?)",
        (guest_id, name, email),
    )


def add_room(conn: sqlite3.Connection, room_id: int, property_id: str, number: str, room_type: str) -> None:
    conn.execute(
        "INSERT INTO rooms(room_id, property_id, number, room_type) VALUES (?,?,?,?)",
        (room_id, property_id, number, room_type),
    )


def get_room(conn: sqlite3.Connection, room_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM rooms WHERE room_id=?", (room_id,)).fetchone()


def add_stay(
    conn: sqlite3.Connection,
    stay_id: str,
    guest_id: str,
    property_id: str,
    room_type: str,
    check_in: int,
    check_out: int,
) -> None:
    conn.execute(
        "INSERT INTO stays(stay_id, guest_id, property_id, room_type, check_in, check_out, status) "
        "VALUES (?,?,?,?,?,?, 'reserved')",
        (stay_id, guest_id, property_id, room_type, int(check_in), int(check_out)),
    )


def get_stay(conn: sqlite3.Connection, stay_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM stays WHERE stay_id=?", (stay_id,)).fetchone()


def set_stay_status(conn: sqlite3.Connection, stay_id: str, status: str) -> None:
    conn.execute("UPDATE stays SET status=? WHERE stay_id=?", (status, stay_id))


def set_stay_room(conn: sqlite3.Connection, stay_id: str, room_id: int) -> None:
    conn.execute("UPDATE stays SET room_id=? WHERE stay_id=?", (room_id, stay_id))


def add_key(conn: sqlite3.Connection, row: dict[str, Any]) -> None:
    conn.execute(
        "INSERT INTO keys(key_id, stay_id, room_id, issued_at, valid_from, valid_until, token, active) "
        "VALUES (:key_id,:stay_id,:room_id,:issued_at,:valid_from,:valid_until,:token,1)",
        row,
    )


def deactivate_keys_for_stay(conn: sqlite3.Connection, stay_id: str) -> list[str]:
    rows = conn.execute(
        "SELECT key_id FROM keys WHERE stay_id=? AND active=1", (stay_id,)
    ).fetchall()
    conn.execute("UPDATE keys SET active=0 WHERE stay_id=? AND active=1", (stay_id,))
    return [r["key_id"] for r in rows]


def revoke_key(conn: sqlite3.Connection, key_id: str, revoked_at: int, reason: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO revocations(key_id, revoked_at, reason) VALUES (?,?,?)",
        (key_id, int(revoked_at), reason),
    )


def revocation_list(conn: sqlite3.Connection) -> list[str]:
    return [r["key_id"] for r in conn.execute("SELECT key_id FROM revocations").fetchall()]


def active_assignment_for_room(conn: sqlite3.Connection, room_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM assignments WHERE room_id=? AND active=1 ORDER BY id DESC LIMIT 1",
        (room_id,),
    ).fetchone()
