"""Pydantic request/response models + the consistent API envelope."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class Envelope(BaseModel):
    ok: bool
    data: Any | None = None
    error: str | None = None


class GuestIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    email: str = Field(min_length=3, max_length=320)


class RoomIn(BaseModel):
    room_id: int = Field(gt=0)
    number: str = Field(min_length=1, max_length=20)
    room_type: str = Field(min_length=1, max_length=40)
    property_id: str | None = None


class ReservationIn(BaseModel):
    guest_id: str | None = None
    guest: GuestIn | None = None
    room_type: str = Field(min_length=1, max_length=40)
    check_in: int = Field(gt=0, description="epoch seconds (UTC)")
    check_out: int = Field(gt=0, description="epoch seconds (UTC)")
    preferred_room_id: int | None = None

    @field_validator("check_out")
    @classmethod
    def _window(cls, v: int, info):  # type: ignore[no-untyped-def]
        ci = info.data.get("check_in")
        if ci is not None and v <= ci:
            raise ValueError("check_out must be after check_in")
        return v


class NowBody(BaseModel):
    now: int | None = Field(default=None, description="optional epoch-seconds override for deterministic demos")


class RoomChangeIn(NowBody):
    new_room_id: int | None = None


class UnlockIn(NowBody):
    token: str
    challenge_b64: str
    response_b64: str


class ControlIn(NowBody):
    token: str
    challenge_b64: str
    response_b64: str
    command: str = Field(min_length=1, max_length=40)
