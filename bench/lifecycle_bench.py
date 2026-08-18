"""Lifecycle correctness bench: issue -> active -> revoked, room-change, and
stay-window boundary enforcement, all recorded as pass/fail booleans."""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path

from staykey import credential, db, keys, lifecycle, reservation
from staykey.app_state import AppState

NOW = 1_800_000_000
DAY = 24 * 3600


def _state() -> AppState:
    return AppState(db_path=Path(tempfile.mkdtemp()) / "lifecycle.sqlite")


def _unlock(state, conn, room_id, key, now):
    lock = state.lock_for(conn, room_id)
    state.sync_lock(conn, room_id)
    ch = lock.begin_unlock(now)
    resp = credential.device_sign(key.device_sk_b64, ch)
    return lock.finish_unlock(token=key.token, challenge=ch, response=resp, now=now)


def _new_stay(state, conn, room_id, room_type="king", check_in=NOW - 3600, check_out=NOW + 3 * DAY):
    gid = "g_" + uuid.uuid4().hex[:8]
    db.add_guest(conn, gid, "Guest", "g@example.com")
    sid = "s_" + uuid.uuid4().hex[:8]
    db.add_stay(conn, sid, gid, state.property_id, room_type, check_in, check_out)
    reservation.assign_room(conn, sid, preferred_room_id=room_id)
    db.set_stay_status(conn, sid, "checked_in")
    return sid


def run() -> dict:
    state = _state()
    conn = state.connect()
    for rid in (101, 102):
        db.add_room(conn, rid, state.property_id, str(rid), "king")

    checks: dict[str, bool] = {}

    # issue -> active unlock
    sid = _new_stay(state, conn, 101)
    key = keys.issue_for_stay(conn, state.property_sk, sid, now=NOW)
    checks["issued_key_unlocks_in_window"] = _unlock(state, conn, 101, key, NOW).unlocked

    # boundaries: before check-in / after check-out
    checks["before_checkin_denied"] = not _unlock(state, conn, 101, key, key.payload["valid_from"] - 1).unlocked
    checks["after_checkout_window_denied"] = not _unlock(state, conn, 101, key, key.payload["valid_until"] + 1).unlocked

    # checkout revokes even within original window
    lifecycle.checkout(conn, sid, now=NOW)
    dec = _unlock(state, conn, 101, key, NOW)
    checks["revoked_after_checkout_denied"] = (not dec.unlocked) and dec.reason.value == "revoked"

    # room change: old key dies, new key works at new room
    sid2 = _new_stay(state, conn, 101)
    key_old = keys.issue_for_stay(conn, state.property_sk, sid2, now=NOW)
    checks["pre_change_old_key_unlocks"] = _unlock(state, conn, 101, key_old, NOW).unlocked
    new_room, revoked, key_new = lifecycle.change_room(conn, state.property_sk, sid2, now=NOW, new_room_id=102)
    checks["room_changed_to_expected"] = new_room == 102
    checks["old_key_denied_after_change"] = not _unlock(state, conn, 101, key_old, NOW).unlocked
    checks["new_key_unlocks_new_room"] = _unlock(state, conn, 102, key_new, NOW).unlocked
    checks["new_key_wrong_room_denied"] = not _unlock(state, conn, 101, key_new, NOW).unlocked

    return {
        "checks": checks,
        "all_correct": all(checks.values()),
        "note": "issue->active->revoked lifecycle, room-change re-keying, and "
        "before/after stay-window boundary enforcement all verified.",
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2))
