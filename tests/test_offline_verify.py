"""Legit in-window keys unlock; single explicit adversarial cases deny."""

from __future__ import annotations

from staykey import credential, db, keys
from tests.conftest import NOW, DAY, make_checked_in_stay, present


def test_legit_in_window_key_unlocks(seeded):
    state = seeded
    conn = state.connect()
    _, issued = make_checked_in_stay(state, conn, 101)
    assert present(state, conn, 101, issued, NOW).unlocked


def test_wrong_room_denied(seeded):
    state = seeded
    conn = state.connect()
    _, issued = make_checked_in_stay(state, conn, 101)
    # present the room-101 key at the room-102 lock
    dec = present(state, conn, 102, issued, NOW)
    assert not dec.unlocked and dec.reason.value == "wrong_room"


def test_before_and_after_window_denied(seeded):
    state = seeded
    conn = state.connect()
    _, issued = make_checked_in_stay(state, conn, 101, check_in=NOW, check_out=NOW + DAY)
    before = present(state, conn, 101, issued, NOW - 5)
    after = present(state, conn, 101, issued, issued.payload["valid_until"] + 5)
    assert not before.unlocked and before.reason.value == "not_yet_valid"
    assert not after.unlocked and after.reason.value == "expired"


def test_bad_device_response_denied(seeded):
    state = seeded
    conn = state.connect()
    _, issued = make_checked_in_stay(state, conn, 101)
    dec = present(state, conn, 101, issued, NOW, wrong_device=True)
    assert not dec.unlocked and dec.reason.value == "bad_response"


def test_short_ttl_expiry(state):
    """A key issued with a short rolling TTL expires before checkout time."""
    conn = state.connect()
    db.add_room(conn, 201, state.property_id, "201", "king")
    # stay spans 10 days but the rolling TTL caps validity sooner
    from staykey import config

    long_out = NOW + 10 * DAY
    _, issued = make_checked_in_stay(state, conn, 201, check_in=NOW, check_out=long_out)
    assert issued.payload["valid_until"] == NOW + config.KEY_TTL_SECONDS
    past_ttl = issued.payload["valid_until"] + 1
    dec = present(state, conn, 201, issued, past_ttl)
    assert not dec.unlocked and dec.reason.value == "expired"
