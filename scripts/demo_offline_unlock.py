"""End-to-end OFFLINE unlock/deny demo (no server, no network).

Shows the whole Digital Key lifecycle against a door lock that holds ONLY the
property public key + a revocation list:

  reserve -> check-in (issue signed key) -> OFFLINE unlock (challenge-response)
  -> adversarial denials -> checkout revokes -> revoked key denied
  -> connected-room control scoped to the stay.

Run:  python -m scripts.demo_offline_unlock
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from staykey import config, credential, db, keys, lifecycle, reservation
from staykey.app_state import AppState
from staykey.lock import LockVerifier

NOW = 1_800_000_000
DAY = 24 * 3600
G = "\033[32m"; R = "\033[31m"; B = "\033[1m"; X = "\033[0m"


def line(label: str, decision, expect_unlock: bool) -> None:
    ok = decision.unlocked == expect_unlock
    verdict = f"{G}UNLOCK{X}" if decision.unlocked else f"{R}DENY ({decision.reason.value}){X}"
    mark = f"{G}OK{X}" if ok else f"{R}WRONG{X}"
    print(f"  [{mark}] {label:<42} -> {verdict}")


def present(lock: LockVerifier, token, device_sk_b64, now, *, wrong_device=False):
    challenge = lock.begin_unlock(now)
    if wrong_device:
        response = Ed25519PrivateKey.generate().sign(challenge)
    else:
        response = credential.device_sign(device_sk_b64, challenge)
    return lock.finish_unlock(token=token, challenge=challenge, response=response, now=now)


def main() -> None:
    state = AppState(
        db_path=Path(tempfile.mkdtemp()) / "demo.sqlite",
        property_sk_path=Path(tempfile.mkdtemp()) / "prop.pem",
    )
    conn = state.connect()
    db.add_room(conn, 101, state.property_id, "101", "king")
    db.add_room(conn, 102, state.property_id, "102", "king")

    print(f"\n{B}StayKey — offline Digital Key demo{X}  (property {state.property_id})")
    print(f"{B}1) Reserve + check-in + issue signed key{X}")
    gid = "g_ada"; db.add_guest(conn, gid, "Ada Lovelace", "ada@example.com")
    sid = "s_ada"; db.add_stay(conn, sid, gid, state.property_id, "king", NOW - 3600, NOW + 3 * DAY)
    room = reservation.assign_room(conn, sid, preferred_room_id=101)
    db.set_stay_status(conn, sid, "checked_in")
    key = keys.issue_for_stay(conn, state.property_sk, sid, now=NOW)
    print(f"  assigned room {room}; key_id={key.key_id[:12]}...  window=[{key.payload['valid_from']}, {key.payload['valid_until']}]")

    # Build the OFFLINE lock for room 101 from ONLY the property pubkey + revocation list.
    print(f"\n{B}2) OFFLINE lock (holds only property public key + revocation list){X}")
    lock = LockVerifier(
        property_id=state.property_id, room_id=101,
        property_pub_raw=state.property_pub_raw, revoked=db.revocation_list(conn),
    )
    line("legitimate in-window key", present(lock, key.token, key.device_sk_b64, NOW), True)

    print(f"\n{B}3) Adversarial presentations (all must DENY){X}")
    # wrong room: a room-102 key at this room-101 lock
    other = credential.issue_credential(property_sk=state.property_sk, guest_id=gid, stay_id=sid,
                                        property_id=state.property_id, room_ids=[102],
                                        valid_from=NOW - 10, valid_until=NOW + 10, issued_at=NOW - 10)
    line("wrong-room key", present(lock, other.token, other.device_sk_b64, NOW), False)
    # expired
    exp = credential.issue_credential(property_sk=state.property_sk, guest_id=gid, stay_id=sid,
                                      property_id=state.property_id, room_ids=[101],
                                      valid_from=NOW - 100, valid_until=NOW - 50, issued_at=NOW - 100)
    line("expired key", present(lock, exp.token, exp.device_sk_b64, NOW), False)
    # not-yet-valid
    fut = credential.issue_credential(property_sk=state.property_sk, guest_id=gid, stay_id=sid,
                                      property_id=state.property_id, room_ids=[101],
                                      valid_from=NOW + 100, valid_until=NOW + 200, issued_at=NOW)
    line("not-yet-valid key (before check-in)", present(lock, fut.token, fut.device_sk_b64, NOW), False)
    # forged (attacker key)
    forged = credential.issue_credential(property_sk=Ed25519PrivateKey.generate(), guest_id=gid, stay_id=sid,
                                         property_id=state.property_id, room_ids=[101],
                                         valid_from=NOW - 10, valid_until=NOW + 10, issued_at=NOW - 10)
    line("forged signature (attacker key)", present(lock, forged.token, forged.device_sk_b64, NOW), False)
    # tampered payload
    from staykey.credential import _b64u_encode, canonical_bytes
    p = dict(key.payload); p["valid_until"] = NOW + 10_000_000
    tampered = f"{_b64u_encode(canonical_bytes(p))}.{key.token.split('.')[1]}"
    line("tampered payload (extended window)", present(lock, tampered, key.device_sk_b64, NOW), False)
    # impersonation: valid token, attacker lacks the device key
    line("stolen token, no device key", present(lock, key.token, key.device_sk_b64, NOW, wrong_device=True), False)
    # replay
    ch = lock.begin_unlock(NOW); resp = credential.device_sign(key.device_sk_b64, ch)
    first = lock.finish_unlock(token=key.token, challenge=ch, response=resp, now=NOW)
    replay = lock.finish_unlock(token=key.token, challenge=ch, response=resp, now=NOW)
    line(f"replayed presentation (1st={first.outcome.value})", replay, False)

    print(f"\n{B}4) Checkout revokes the key (synced to the lock){X}")
    revoked = lifecycle.checkout(conn, sid, now=NOW)
    lock.sync_revocations(db.revocation_list(conn))
    print(f"  revoked key_ids: {[k[:12] + '...' for k in revoked]}")
    line("revoked key within its original window", present(lock, key.token, key.device_sk_b64, NOW), False)

    print(f"\n{B}5) Connected-Room control scoped to the active stay{X}")
    gid2 = "g_ben"; db.add_guest(conn, gid2, "Ben", "ben@example.com")
    sid2 = "s_ben"; db.add_stay(conn, sid2, gid2, state.property_id, "king", NOW - 3600, NOW + 3 * DAY)
    reservation.assign_room(conn, sid2, preferred_room_id=101)
    db.set_stay_status(conn, sid2, "checked_in")
    key2 = keys.issue_for_stay(conn, state.property_sk, sid2, now=NOW)

    def control(room_id, k, cmd, wrong_device=False):
        challenge = state.connected.begin_command(NOW)
        response = (Ed25519PrivateKey.generate().sign(challenge) if wrong_device
                    else credential.device_sign(k.device_sk_b64, challenge))
        return state.connected.authorize(conn, room_id=room_id, command=cmd, token=k.token,
                                         challenge=challenge, response=response, now=NOW)

    d = control(101, key2, "thermostat")
    print(f"  [{'OK' if d.allowed else 'WRONG'}] guest controls own room 101 thermostat -> {'ALLOW' if d.allowed else 'DENY'}")
    d2 = control(102, key2, "tv")
    print(f"  [{'OK' if not d2.allowed else 'WRONG'}] guest tries room 102 TV (cross-room) -> {'ALLOW' if d2.allowed else 'DENY (' + d2.reason.value + ')'}")

    print(f"\n{G}{B}Demo complete — every adversarial presentation was denied, offline.{X}\n")


if __name__ == "__main__":
    main()
