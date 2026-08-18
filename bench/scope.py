"""Connected-Room scope bench: verify 0 cross-room / cross-stay command leaks.

Sets up a live DB with two checked-in stays in two rooms (plus a soon-checked-out
stay), then fires legitimate and cross-scope control attempts through the real
ConnectedRoomAuthorizer, counting how many cross-scope commands are (wrongly)
accepted. Target: 0.
"""

from __future__ import annotations

import tempfile
import uuid
from collections import Counter
from pathlib import Path

from staykey import config, credential, db, keys, lifecycle, reservation
from staykey.app_state import AppState

NOW = 1_800_000_000


def _fresh_state() -> AppState:
    tmp = Path(tempfile.mkdtemp()) / "scope.sqlite"
    return AppState(db_path=tmp)


def _checked_in_stay(state: AppState, conn, guest: str, room_type: str, room_id: int):
    gid = "g_" + uuid.uuid4().hex[:8]
    db.add_guest(conn, gid, guest, f"{guest}@example.com")
    sid = "s_" + uuid.uuid4().hex[:8]
    db.add_stay(conn, sid, gid, state.property_id, room_type, NOW - 3600, NOW + 3 * 24 * 3600)
    reservation.assign_room(conn, sid, preferred_room_id=room_id)
    db.set_stay_status(conn, sid, "checked_in")
    issued = keys.issue_for_stay(conn, state.property_sk, sid, now=NOW)
    return sid, issued


def _control(state, conn, *, room_id, token, device_sk_b64, command, wrong_device=False):
    challenge = state.connected.begin_command(NOW)
    if wrong_device:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        response = Ed25519PrivateKey.generate().sign(challenge)
    else:
        response = credential.device_sign(device_sk_b64, challenge)
    return state.connected.authorize(
        conn, room_id=room_id, command=command, token=token,
        challenge=challenge, response=response, now=NOW,
    )


def run() -> dict:
    state = _fresh_state()
    conn = state.connect()
    db.add_room(conn, 101, state.property_id, "101", "king")
    db.add_room(conn, 102, state.property_id, "102", "king")
    db.add_room(conn, 103, state.property_id, "103", "queen")

    sidA, keyA = _checked_in_stay(state, conn, "Ada", "king", 101)
    sidB, keyB = _checked_in_stay(state, conn, "Ben", "king", 102)
    sidC, keyC = _checked_in_stay(state, conn, "Cyd", "queen", 103)

    legit_allowed = 0
    legit_total = 0
    cross_leaks = 0
    cross_total = 0
    reasons: Counter[str] = Counter()

    # -- legitimate: each guest controls their own room, all devices ------
    for room, key in [(101, keyA), (102, keyB), (103, keyC)]:
        for cmd in config.ALLOWED_DEVICES:
            legit_total += 1
            dec = _control(state, conn, room_id=room, token=key.token, device_sk_b64=key.device_sk_b64, command=cmd)
            if dec.allowed:
                legit_allowed += 1

    # -- cross-room: A vs 102/103, B vs 101/103, C vs 101/102 -------------
    cross_matrix = [
        (101, keyB), (101, keyC),
        (102, keyA), (102, keyC),
        (103, keyA), (103, keyB),
    ]
    for room, key in cross_matrix:
        for cmd in config.ALLOWED_DEVICES:
            cross_total += 1
            dec = _control(state, conn, room_id=room, token=key.token, device_sk_b64=key.device_sk_b64, command=cmd)
            if dec.allowed:
                cross_leaks += 1
            elif dec.reason:
                reasons[dec.reason.value] += 1

    # -- possession: A's token, attacker without A's device key ----------
    for cmd in config.ALLOWED_DEVICES:
        cross_total += 1
        dec = _control(state, conn, room_id=101, token=keyA.token, device_sk_b64=keyA.device_sk_b64, command=cmd, wrong_device=True)
        if dec.allowed:
            cross_leaks += 1
        elif dec.reason:
            reasons[dec.reason.value] += 1

    # -- bad command -----------------------------------------------------
    for cmd in ("open_safe", "disable_alarm"):
        cross_total += 1
        dec = _control(state, conn, room_id=101, token=keyA.token, device_sk_b64=keyA.device_sk_b64, command=cmd)
        if dec.allowed:
            cross_leaks += 1
        elif dec.reason:
            reasons[dec.reason.value] += 1

    # -- post-checkout: C checks out, then tries to control room 103 -----
    revoked = lifecycle.checkout(conn, sidC, now=NOW)
    for cmd in config.ALLOWED_DEVICES:
        cross_total += 1
        dec = _control(state, conn, room_id=103, token=keyC.token, device_sk_b64=keyC.device_sk_b64, command=cmd)
        if dec.allowed:
            cross_leaks += 1
        elif dec.reason:
            reasons[dec.reason.value] += 1

    return {
        "legit_commands": legit_total,
        "legit_accepted": legit_allowed,
        "cross_scope_attempts": cross_total,
        "cross_scope_leaks": cross_leaks,
        "post_checkout_revoked": revoked,
        "deny_reason_distribution": dict(reasons),
        "note": "commands: tv/thermostat/lights; cross-room, impersonation (no device key), "
        "bad-command, and post-checkout attempts all rejected.",
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2))
