"""Application wiring: property keypair, DB, in-process simulated locks.

The lock registry holds one `LockVerifier` per room (an in-process SIMULATION of
the offline lock inside a door). Each lock is seeded and periodically re-synced
with the revocation list from the DB via `sync_lock` — mirroring how a real lock
receives revocations out of band, then verifies presented keys entirely offline.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from . import config, db, keys
from .connectedroom import ConnectedRoomAuthorizer
from .lock import LockVerifier

DEMO_PROPERTY_ID = "HILTON-DEMO-001"


class AppState:
    def __init__(
        self,
        db_path: Path | str | None = None,
        property_id: str = DEMO_PROPERTY_ID,
        property_sk_path: Path | str | None = None,
    ) -> None:
        self.db_path = str(db_path or config.DB_PATH)
        self.property_id = property_id
        self.property_sk = keys.load_or_create_property_key(
            Path(property_sk_path) if property_sk_path else None
        )
        self.property_pub_raw = keys.property_public_raw(self.property_sk)
        self._locks: dict[int, LockVerifier] = {}
        self.connected = ConnectedRoomAuthorizer(
            property_id=property_id, property_pub_raw=self.property_pub_raw
        )
        with self.connect() as conn:
            db.init_db(conn)

    def connect(self) -> sqlite3.Connection:
        return db.connect(self.db_path)

    # -- lock registry (simulated offline locks) ---------------------------
    def lock_for(self, conn: sqlite3.Connection, room_id: int) -> LockVerifier:
        room_id = int(room_id)
        lock = self._locks.get(room_id)
        if lock is None:
            room = db.get_room(conn, room_id)
            prop = room["property_id"] if room is not None else self.property_id
            lock = LockVerifier(
                property_id=prop,
                room_id=room_id,
                property_pub_raw=self.property_pub_raw,
                revoked=db.revocation_list(conn),
            )
            self._locks[room_id] = lock
        return lock

    def sync_lock(self, conn: sqlite3.Connection, room_id: int) -> None:
        """Simulate a periodic OTA revocation sync to one lock."""
        lock = self.lock_for(conn, room_id)
        lock.sync_revocations(db.revocation_list(conn))

    def sync_all_locks(self, conn: sqlite3.Connection) -> None:
        revoked = db.revocation_list(conn)
        for lock in self._locks.values():
            lock.sync_revocations(revoked)
