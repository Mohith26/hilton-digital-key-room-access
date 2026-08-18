"""Connected-Room controls are scoped to the active stay: 0 cross-scope leaks."""

from __future__ import annotations

from staykey import config, credential, db, lifecycle
from staykey.app_state import AppState
from tests.conftest import NOW, make_checked_in_stay
from bench import scope


def _cmd(state: AppState, conn, room_id, issued, command, *, wrong_device=False):
    challenge = state.connected.begin_command(NOW)
    if wrong_device:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        response = Ed25519PrivateKey.generate().sign(challenge)
    else:
        response = credential.device_sign(issued.device_sk_b64, challenge)
    return state.connected.authorize(
        conn, room_id=room_id, command=command, token=issued.token,
        challenge=challenge, response=response, now=NOW,
    )


def test_guest_controls_own_room(seeded):
    state = seeded
    conn = state.connect()
    _, key = make_checked_in_stay(state, conn, 101)
    for cmd in config.ALLOWED_DEVICES:
        assert _cmd(state, conn, 101, key, cmd).allowed


def test_cross_room_command_rejected(seeded):
    state = seeded
    conn = state.connect()
    _, keyA = make_checked_in_stay(state, conn, 101)
    _, keyB = make_checked_in_stay(state, conn, 102)
    assert not _cmd(state, conn, 102, keyA, "tv").allowed          # A can't drive room 102
    assert not _cmd(state, conn, 101, keyB, "lights").allowed      # B can't drive room 101


def test_impersonation_and_bad_command_rejected(seeded):
    state = seeded
    conn = state.connect()
    _, key = make_checked_in_stay(state, conn, 101)
    assert not _cmd(state, conn, 101, key, "tv", wrong_device=True).allowed
    bad = _cmd(state, conn, 101, key, "open_safe")
    assert not bad.allowed and bad.reason.value == "bad_command"


def test_post_checkout_command_rejected(seeded):
    state = seeded
    conn = state.connect()
    sid, key = make_checked_in_stay(state, conn, 101)
    assert _cmd(state, conn, 101, key, "tv").allowed
    lifecycle.checkout(conn, sid, now=NOW)
    dec = _cmd(state, conn, 101, key, "tv")
    assert not dec.allowed and dec.reason.value == "revoked"


def test_scope_bench_zero_leaks():
    result = scope.run()
    assert result["cross_scope_leaks"] == 0
    assert result["legit_accepted"] == result["legit_commands"]
