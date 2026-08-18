"""Checkout / room-change revoke keys; revoked keys deny within their window."""

from __future__ import annotations

from staykey import credential, db, keys, lifecycle
from tests.conftest import NOW, DAY, make_checked_in_stay, present


def test_checkout_revokes_within_original_window(seeded):
    state = seeded
    conn = state.connect()
    sid, issued = make_checked_in_stay(state, conn, 101)
    assert present(state, conn, 101, issued, NOW).unlocked  # active

    revoked = lifecycle.checkout(conn, sid, now=NOW)
    assert issued.key_id in revoked
    dec = present(state, conn, 101, issued, NOW)  # still inside valid window
    assert not dec.unlocked and dec.reason.value == "revoked"


def test_room_change_rekeys(seeded):
    state = seeded
    conn = state.connect()
    sid, old = make_checked_in_stay(state, conn, 101)
    assert present(state, conn, 101, old, NOW).unlocked

    new_room, revoked, new_key = lifecycle.change_room(conn, state.property_sk, sid, now=NOW, new_room_id=102)
    assert new_room == 102
    assert old.key_id in revoked
    # old key dead at old room; new key opens new room; new key wrong at old room
    assert not present(state, conn, 101, old, NOW).unlocked
    assert present(state, conn, 102, new_key, NOW).unlocked
    assert not present(state, conn, 101, new_key, NOW).unlocked


def test_refresh_issues_new_key_without_revoking_old(seeded):
    state = seeded
    conn = state.connect()
    sid, first = make_checked_in_stay(state, conn, 101)
    second = lifecycle.refresh_key(conn, state.property_sk, sid, now=NOW)
    assert second.key_id != first.key_id
    # rolling-key model: refresh does NOT revoke; both remain valid until TTL
    assert first.key_id not in db.revocation_list(conn)
    assert present(state, conn, 101, second, NOW).unlocked
    assert present(state, conn, 101, first, NOW).unlocked


def test_revocation_list_syncs_to_lock(seeded):
    state = seeded
    conn = state.connect()
    sid, issued = make_checked_in_stay(state, conn, 101)
    lock = state.lock_for(conn, 101)
    assert issued.key_id not in lock.revoked_snapshot
    lifecycle.checkout(conn, sid, now=NOW)
    state.sync_lock(conn, 101)
    assert issued.key_id in lock.revoked_snapshot
