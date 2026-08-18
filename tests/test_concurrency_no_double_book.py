"""Concurrency: many threads race for the same room+window; exactly one wins,
and no room is ever assigned to two overlapping stays."""

from __future__ import annotations

from bench import concurrency


def test_single_room_race_exactly_one_winner():
    result = concurrency.run()
    single = result["single_room_race"]
    assert single["threads"] == 32
    assert single["successes"] == 1
    assert single["assignments_for_room"] == 1
    assert single["double_booked"] == 0
    assert single["room_unavailable_rejections"] == 31


def test_multi_room_race_no_shared_room():
    result = concurrency.run()
    multi = result["multi_room_race"]
    assert multi["assigned"] == multi["rooms"] == 10
    assert multi["distinct_rooms_used"] == 10
    assert multi["duplicate_room_assignments"] == 0


def test_no_double_book_total_is_zero():
    assert concurrency.run()["double_booked_total"] == 0
