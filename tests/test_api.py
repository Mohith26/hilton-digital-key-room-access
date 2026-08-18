"""End-to-end API tests via FastAPI TestClient (in-process ASGI)."""

from __future__ import annotations

import base64
import time

from staykey import credential

NOW = int(time.time())
DAY = 24 * 3600


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _seed_room(client, room_id=101, room_type="king"):
    r = client.post("/rooms", json={"room_id": room_id, "number": str(room_id), "room_type": room_type})
    assert r.status_code == 200 and r.json()["ok"]


def _reserve_and_checkin(client, room_type="king", preferred=101):
    res = client.post("/reservations", json={
        "guest": {"name": "Ada", "email": "ada@example.com"},
        "room_type": room_type, "check_in": NOW - 3600, "check_out": NOW + 3 * DAY,
        "preferred_room_id": preferred,
    })
    assert res.status_code == 200, res.text
    stay_id = res.json()["data"]["stay_id"]
    ci = client.post(f"/checkin/{stay_id}")
    assert ci.status_code == 200, ci.text
    return stay_id, ci.json()["data"]


def _unlock(client, room_id, key, *, now=None):
    ch = client.post(f"/lock/{room_id}/challenge").json()["data"]["challenge_b64"]
    response = credential.device_sign(key["device_sk_b64"], _b64d(ch))
    resp_b64 = base64.urlsafe_b64encode(response).rstrip(b"=").decode()
    body = {"token": key["token"], "challenge_b64": ch, "response_b64": resp_b64}
    if now is not None:
        body["now"] = now
    return client.post(f"/lock/{room_id}/unlock", json=body).json()["data"]


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["data"]["status"] == "up"


def test_full_flow_unlock(client):
    _seed_room(client)
    _, key = _reserve_and_checkin(client)
    assert _unlock(client, 101, key)["unlocked"] is True


def test_tampered_token_denied_via_api(client):
    _seed_room(client)
    _, key = _reserve_and_checkin(client)
    tampered = dict(key)
    # flip a character in the payload segment
    payload_seg, sig_seg = key["token"].split(".")
    flipped = payload_seg[:-2] + ("aa" if payload_seg[-2:] != "aa" else "bb")
    tampered["token"] = f"{flipped}.{sig_seg}"
    out = _unlock(client, 101, tampered)
    assert out["unlocked"] is False and out["reason"] in ("forged_signature", "malformed")


def test_checkout_revokes_via_api(client):
    _seed_room(client)
    stay_id, key = _reserve_and_checkin(client)
    assert _unlock(client, 101, key)["unlocked"] is True
    co = client.post(f"/checkout/{stay_id}")
    assert co.status_code == 200
    assert key["key_id"] in co.json()["data"]["revoked_key_ids"]
    out = _unlock(client, 101, key)
    assert out["unlocked"] is False and out["reason"] == "revoked"


def test_double_book_conflict_via_api(client):
    _seed_room(client, 101)
    # first reservation grabs room 101
    _reserve_and_checkin(client, preferred=101)
    # a second overlapping reservation preferring the same room -> 409
    r = client.post("/reservations", json={
        "guest": {"name": "Ben", "email": "ben@example.com"},
        "room_type": "king", "check_in": NOW, "check_out": NOW + DAY,
        "preferred_room_id": 101,
    })
    assert r.status_code == 409


def test_connected_room_control_via_api(client):
    _seed_room(client, 101)
    _seed_room(client, 102)
    stayA, keyA = _reserve_and_checkin(client, preferred=101)

    def control(room_id, key, command):
        ch = client.post(f"/room/{room_id}/challenge").json()["data"]["challenge_b64"]
        response = credential.device_sign(key["device_sk_b64"], _b64d(ch))
        resp_b64 = base64.urlsafe_b64encode(response).rstrip(b"=").decode()
        return client.post(f"/room/{room_id}/control", json={
            "token": key["token"], "challenge_b64": ch, "response_b64": resp_b64, "command": command,
        }).json()["data"]

    assert control(101, keyA, "tv")["applied"] is True
    # cross-room command rejected
    assert control(102, keyA, "lights")["applied"] is False


def test_validation_rejects_bad_window(client):
    r = client.post("/reservations", json={
        "guest": {"name": "X", "email": "x@example.com"},
        "room_type": "king", "check_in": NOW + DAY, "check_out": NOW,  # invalid
    })
    assert r.status_code == 422  # pydantic validation
