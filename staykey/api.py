"""FastAPI application: reserve, check-in, refresh, checkout, room-change,
lock/verify (simulated presentation), and connected-room control.

Consistent envelope on every response: {ok, data, error}. Input is validated by
pydantic models; domain errors map to 4xx. Times are epoch seconds; verify/control
endpoints accept an optional `now` override for deterministic demos (the lock's
clock is a verification input, exactly as a real lock uses its own RTC).
"""

from __future__ import annotations

import base64
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import db, keys, lifecycle, reservation
from .app_state import AppState
from .errors import (
    NotFoundError,
    RoomUnavailableError,
    StayKeyError,
    UnlockOutcome,
    ValidationError,
)
from .models import ControlIn, Envelope, GuestIn, ReservationIn, RoomChangeIn, RoomIn, UnlockIn


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _now(override: int | None) -> int:
    return int(override) if override is not None else int(time.time())


def _ok(data=None) -> Envelope:
    return Envelope(ok=True, data=data)


def create_app(state: AppState | None = None) -> FastAPI:
    app = FastAPI(title="StayKey — Hilton-style Digital Key", version="1.0.0")
    app.state.ctx = state or AppState()

    def ctx() -> AppState:
        return app.state.ctx

    # -- error handling ---------------------------------------------------
    @app.exception_handler(NotFoundError)
    async def _nf(_: Request, exc: NotFoundError):
        return JSONResponse(status_code=404, content=Envelope(ok=False, error=str(exc)).model_dump())

    @app.exception_handler(RoomUnavailableError)
    async def _ru(_: Request, exc: RoomUnavailableError):
        return JSONResponse(status_code=409, content=Envelope(ok=False, error=str(exc)).model_dump())

    @app.exception_handler(ValidationError)
    async def _val(_: Request, exc: ValidationError):
        return JSONResponse(status_code=400, content=Envelope(ok=False, error=str(exc)).model_dump())

    @app.exception_handler(StayKeyError)
    async def _domain(_: Request, exc: StayKeyError):
        return JSONResponse(status_code=400, content=Envelope(ok=False, error=str(exc)).model_dump())

    # -- health / inventory ----------------------------------------------
    @app.get("/health", response_model=Envelope)
    def health():
        with ctx().connect() as conn:
            counts = {
                t: conn.execute(f"SELECT COUNT(*) c FROM {t}").fetchone()["c"]
                for t in ("guests", "rooms", "stays", "keys", "revocations")
            }
        return _ok({"status": "up", "property_id": ctx().property_id, "counts": counts})

    @app.post("/guests", response_model=Envelope)
    def create_guest(body: GuestIn):
        guest_id = "g_" + uuid.uuid4().hex[:12]
        with ctx().connect() as conn:
            db.add_guest(conn, guest_id, body.name, body.email)
        return _ok({"guest_id": guest_id})

    @app.post("/rooms", response_model=Envelope)
    def create_room(body: RoomIn):
        with ctx().connect() as conn:
            db.add_room(conn, body.room_id, body.property_id or ctx().property_id, body.number, body.room_type)
        return _ok({"room_id": body.room_id})

    # -- reservation + assignment ----------------------------------------
    @app.post("/reservations", response_model=Envelope)
    def reserve(body: ReservationIn):
        with ctx().connect() as conn:
            guest_id = body.guest_id
            if guest_id is None:
                if body.guest is None:
                    raise ValidationError("provide guest_id or guest")
                guest_id = "g_" + uuid.uuid4().hex[:12]
                db.add_guest(conn, guest_id, body.guest.name, body.guest.email)
            elif conn.execute("SELECT 1 FROM guests WHERE guest_id=?", (guest_id,)).fetchone() is None:
                raise NotFoundError(f"guest {guest_id} not found")

            stay_id = "s_" + uuid.uuid4().hex[:12]
            db.add_stay(conn, stay_id, guest_id, ctx().property_id, body.room_type, body.check_in, body.check_out)
            room_id = reservation.assign_room(conn, stay_id, preferred_room_id=body.preferred_room_id)
        return _ok({"stay_id": stay_id, "guest_id": guest_id, "room_id": room_id})

    # -- check-in -> key issuance ----------------------------------------
    @app.post("/checkin/{stay_id}", response_model=Envelope)
    def checkin(stay_id: str):
        with ctx().connect() as conn:
            stay = db.get_stay(conn, stay_id)
            if stay is None:
                raise NotFoundError(f"stay {stay_id} not found")
            db.set_stay_status(conn, stay_id, "checked_in")
            issued = keys.issue_for_stay(conn, ctx().property_sk, stay_id, now=_now(None))
        return _ok(_key_payload(issued))

    @app.post("/keys/{stay_id}/refresh", response_model=Envelope)
    def refresh(stay_id: str):
        with ctx().connect() as conn:
            issued = lifecycle.refresh_key(conn, ctx().property_sk, stay_id, now=_now(None))
        return _ok(_key_payload(issued))

    @app.post("/checkout/{stay_id}", response_model=Envelope)
    def checkout(stay_id: str):
        with ctx().connect() as conn:
            stay = db.get_stay(conn, stay_id)
            if stay is None:
                raise NotFoundError(f"stay {stay_id} not found")
            room_id = stay["room_id"]
            revoked = lifecycle.checkout(conn, stay_id, now=_now(None))
            if room_id is not None:
                ctx().sync_lock(conn, int(room_id))  # periodic OTA sync (simulated)
        return _ok({"revoked_key_ids": revoked, "synced_room": room_id})

    @app.post("/stays/{stay_id}/room-change", response_model=Envelope)
    def room_change(stay_id: str, body: RoomChangeIn):
        with ctx().connect() as conn:
            stay = db.get_stay(conn, stay_id)
            if stay is None:
                raise NotFoundError(f"stay {stay_id} not found")
            old_room = stay["room_id"]
            new_room, revoked, issued = lifecycle.change_room(
                conn, ctx().property_sk, stay_id, now=_now(body.now), new_room_id=body.new_room_id
            )
            if old_room is not None:
                ctx().sync_lock(conn, int(old_room))
            ctx().sync_lock(conn, int(new_room))
        return _ok({"new_room_id": new_room, "revoked_key_ids": revoked, "key": _key_payload(issued)})

    @app.get("/revocations", response_model=Envelope)
    def revocations():
        with ctx().connect() as conn:
            return _ok({"revoked_key_ids": db.revocation_list(conn)})

    # -- lock (offline verifier, simulated presentation) -----------------
    @app.post("/lock/{room_id}/challenge", response_model=Envelope)
    def lock_challenge(room_id: int, body: UnlockIn | None = None):
        with ctx().connect() as conn:
            lock = ctx().lock_for(conn, room_id)
        challenge = lock.begin_unlock(_now(None))
        return _ok({"challenge_b64": _b64e(challenge)})

    @app.post("/lock/{room_id}/unlock", response_model=Envelope)
    def lock_unlock(room_id: int, body: UnlockIn):
        with ctx().connect() as conn:
            ctx().sync_lock(conn, room_id)  # ensure lock has latest synced revocations
            lock = ctx().lock_for(conn, room_id)
        decision = lock.finish_unlock(
            token=body.token,
            challenge=_b64d(body.challenge_b64),
            response=_b64d(body.response_b64),
            now=_now(body.now),
        )
        return _ok(_decision_payload(decision))

    # -- connected room ---------------------------------------------------
    @app.post("/room/{room_id}/challenge", response_model=Envelope)
    def room_challenge(room_id: int):
        challenge = ctx().connected.begin_command(_now(None))
        return _ok({"challenge_b64": _b64e(challenge)})

    @app.post("/room/{room_id}/control", response_model=Envelope)
    def room_control(room_id: int, body: ControlIn):
        with ctx().connect() as conn:
            decision = ctx().connected.authorize(
                conn,
                room_id=room_id,
                command=body.command,
                token=body.token,
                challenge=_b64d(body.challenge_b64),
                response=_b64d(body.response_b64),
                now=_now(body.now),
            )
        payload = _decision_payload(decision)
        payload["command"] = body.command
        payload["applied"] = decision.allowed
        return _ok(payload)

    return app


def _key_payload(issued) -> dict:
    return {
        "key_id": issued.key_id,
        "token": issued.token,
        "device_sk_b64": issued.device_sk_b64,  # goes to the guest phone only
        "valid_from": issued.payload["valid_from"],
        "valid_until": issued.payload["valid_until"],
        "room_ids": issued.payload["room_ids"],
    }


def _decision_payload(decision) -> dict:
    return {
        "outcome": decision.outcome.value,
        "unlocked": decision.outcome is UnlockOutcome.UNLOCK,
        "reason": decision.reason.value if decision.reason else None,
        "key_id": decision.key_id,
    }


# Module-level app for `uvicorn staykey.api:app`. Creates data dir + property key
# on import; tests build their own app via create_app(AppState(tmp_db)).
app = create_app()

