"""Overlap-safe assignment: no two overlapping stays share a room."""

from __future__ import annotations

import uuid

from staykey import db, reservation
from staykey.errors import RoomUnavailableError
from tests.conftest import NOW, DAY


def _stay(conn, state, room_type, check_in, check_out):
    gid = "g_" + uuid.uuid4().hex[:8]
    db.add_guest(conn, gid, "G", "g@example.com")
    sid = "s_" + uuid.uuid4().hex[:8]
    db.add_stay(conn, sid, gid, state.property_id, room_type, check_in, check_out)
    return sid


def test_second_overlapping_stay_cannot_take_same_room(seeded):
    state = seeded
    conn = state.connect()
    s1 = _stay(conn, state, "king", NOW, NOW + 2 * DAY)
    s2 = _stay(conn, state, "king", NOW + DAY, NOW + 3 * DAY)  # overlaps s1
    r1 = reservation.assign_room(conn, s1, preferred_room_id=101)
    with __import__("pytest").raises(RoomUnavailableError):
        reservation.assign_room(conn, s2, preferred_room_id=101)
    assert r1 == 101


def test_auto_assign_picks_a_free_room_for_overlap(seeded):
    state = seeded
    conn = state.connect()
    s1 = _stay(conn, state, "king", NOW, NOW + 2 * DAY)
    s2 = _stay(conn, state, "king", NOW + DAY, NOW + 3 * DAY)
    r1 = reservation.assign_room(conn, s1)
    r2 = reservation.assign_room(conn, s2)  # auto-assign second king room
    assert {r1, r2} == {101, 102}


def test_non_overlapping_stays_can_reuse_a_room(seeded):
    state = seeded
    conn = state.connect()
    s1 = _stay(conn, state, "king", NOW, NOW + DAY)
    s2 = _stay(conn, state, "king", NOW + DAY, NOW + 2 * DAY)  # touches at boundary (half-open)
    r1 = reservation.assign_room(conn, s1, preferred_room_id=101)
    r2 = reservation.assign_room(conn, s2, preferred_room_id=101)
    assert r1 == r2 == 101  # [a,b) and [b,c) do not overlap


def test_no_room_of_type_raises(seeded):
    state = seeded
    conn = state.connect()
    s1 = _stay(conn, state, "presidential", NOW, NOW + DAY)
    with __import__("pytest").raises(RoomUnavailableError):
        reservation.assign_room(conn, s1)
