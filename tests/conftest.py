"""Shared fixtures: isolated AppState (temp DB + temp property key) and a client."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from staykey import credential, db, keys, reservation
from staykey.api import create_app
from staykey.app_state import AppState

NOW = 1_800_000_000
DAY = 24 * 3600


@pytest.fixture()
def state(tmp_path: Path) -> AppState:
    return AppState(
        db_path=tmp_path / "staykey.sqlite",
        property_sk_path=tmp_path / "property_sk.pem",
    )


@pytest.fixture()
def client(state: AppState) -> TestClient:
    return TestClient(create_app(state))


@pytest.fixture()
def seeded(state: AppState):
    """A state with two king rooms + one queen room."""
    conn = state.connect()
    db.add_room(conn, 101, state.property_id, "101", "king")
    db.add_room(conn, 102, state.property_id, "102", "king")
    db.add_room(conn, 103, state.property_id, "103", "queen")
    conn.close()
    return state


def make_checked_in_stay(state: AppState, conn, room_id: int, room_type="king",
                         check_in=NOW - 3600, check_out=NOW + 3 * DAY):
    gid = "g_" + uuid.uuid4().hex[:8]
    db.add_guest(conn, gid, "Guest", "g@example.com")
    sid = "s_" + uuid.uuid4().hex[:8]
    db.add_stay(conn, sid, gid, state.property_id, room_type, check_in, check_out)
    reservation.assign_room(conn, sid, preferred_room_id=room_id)
    db.set_stay_status(conn, sid, "checked_in")
    issued = keys.issue_for_stay(conn, state.property_sk, sid, now=NOW)
    return sid, issued


def present(state: AppState, conn, room_id: int, issued, now: int, *, wrong_device=False):
    """Drive a full offline challenge-response unlock and return the Decision."""
    state.sync_lock(conn, room_id)
    lock = state.lock_for(conn, room_id)
    challenge = lock.begin_unlock(now)
    if wrong_device:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        response = Ed25519PrivateKey.generate().sign(challenge)
    else:
        response = credential.device_sign(issued.device_sk_b64, challenge)
    return lock.finish_unlock(token=issued.token, challenge=challenge, response=response, now=now)
