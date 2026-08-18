"""Pure Digital-Key credential primitives — issuance, parsing, verification.

SECURITY-CRITICAL and deliberately PURE: this module imports ONLY `cryptography`,
the local `config`/`errors`, and the Python standard library. It has NO database,
network, filesystem, or web-framework dependency, so the offline lock verifier
that builds on it can be proven to need neither a DB nor a network at unlock time
(see tests/test_offline_purity.py).

A credential is a compact signed token:

    token = b64url(canonical_payload_json) + "." + b64url(property_signature)

The payload carries: key_id, guest/stay/property ids, room_ids, valid_from,
valid_until, issued_at, an issuance nonce, and the per-key DEVICE public key.
The property's Ed25519 private key signs the canonical payload bytes. The guest
device also receives a per-key device private key (never shared with the lock);
unlock is a challenge-response proving possession of that device key.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import config
from .errors import Decision, DenyReason

PAYLOAD_VERSION = 1


# --------------------------------------------------------------------------
# Low-level encoding
# --------------------------------------------------------------------------
def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic canonical serialization used for signing and verifying."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------------
# Ed25519 helpers
# --------------------------------------------------------------------------
def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key()


def public_raw(pub: Ed25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_raw(sk: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_from_raw(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def private_from_raw(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


# --------------------------------------------------------------------------
# Issuance
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class IssuedKey:
    """Result of issuing a Digital Key.

    `token` + `device_sk_b64` go to the guest's phone. `device_sk_b64` is the
    per-key device private key the phone uses to answer lock challenges; it is
    NEVER given to the lock (the lock only ever sees the device PUBLIC key that
    is baked into the signed payload).
    """

    key_id: str
    token: str
    device_sk_b64: str
    payload: dict[str, Any]


def issue_credential(
    *,
    property_sk: Ed25519PrivateKey,
    guest_id: str,
    stay_id: str,
    property_id: str,
    room_ids: list[int],
    valid_from: int,
    valid_until: int,
    issued_at: int,
    device_sk: Ed25519PrivateKey | None = None,
    key_id: str | None = None,
    nonce: str | None = None,
) -> IssuedKey:
    """Sign and return a Digital Key credential.

    A fresh per-key device keypair is generated unless one is supplied.
    """
    if valid_until <= valid_from:
        from .errors import ValidationError

        raise ValidationError("valid_until must be after valid_from")
    device_sk = device_sk or Ed25519PrivateKey.generate()
    device_pub_raw = public_raw(device_sk.public_key())

    payload: dict[str, Any] = {
        "v": PAYLOAD_VERSION,
        "key_id": key_id or uuid.uuid4().hex,
        "guest_id": guest_id,
        "stay_id": stay_id,
        "property_id": property_id,
        "room_ids": sorted(int(r) for r in room_ids),
        "valid_from": int(valid_from),
        "valid_until": int(valid_until),
        "issued_at": int(issued_at),
        "nonce": nonce or secrets.token_hex(config.CREDENTIAL_NONCE_BYTES),
        "device_pub": _b64u_encode(device_pub_raw),
    }
    payload_bytes = canonical_bytes(payload)
    signature = property_sk.sign(payload_bytes)
    token = f"{_b64u_encode(payload_bytes)}.{_b64u_encode(signature)}"
    return IssuedKey(
        key_id=payload["key_id"],
        token=token,
        device_sk_b64=_b64u_encode(private_raw(device_sk)),
        payload=payload,
    )


# --------------------------------------------------------------------------
# Parsing + verification
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class ParsedToken:
    payload: dict[str, Any]
    payload_bytes: bytes
    signature: bytes


def parse_token(token: str) -> ParsedToken | None:
    """Parse a token into (payload, payload_bytes, signature). None if malformed."""
    if not isinstance(token, str) or token.count(".") != 1:
        return None
    seg_payload, seg_sig = token.split(".")
    try:
        payload_bytes = _b64u_decode(seg_payload)
        signature = _b64u_decode(seg_sig)
        payload = json.loads(payload_bytes)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or "key_id" not in payload:
        return None
    return ParsedToken(payload=payload, payload_bytes=payload_bytes, signature=signature)


def _signature_ok(property_pub: Ed25519PublicKey, payload_bytes: bytes, signature: bytes) -> bool:
    try:
        property_pub.verify(signature, payload_bytes)
        return True
    except InvalidSignature:
        return False


def verify_device_response(device_pub_b64: str, challenge: bytes, response: bytes) -> bool:
    """True iff `response` is a valid device signature over the lock `challenge`."""
    try:
        device_pub = public_from_raw(_b64u_decode(device_pub_b64))
        device_pub.verify(response, challenge)
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass(frozen=True)
class StaticResult:
    """Outcome of the credential's static (non-challenge) checks."""

    deny: Decision | None          # a deny Decision, or None if all static checks pass
    payload: dict[str, Any] | None


def evaluate_static(
    *,
    token: str,
    property_pub: Ed25519PublicKey,
    expected_property: str,
    expected_room: int,
    now: int,
    revoked: frozenset[str] | set[str],
) -> StaticResult:
    """Run every check that needs ONLY the property public key + revocation list.

    Order matters for meaningful deny reasons. This function does NOT do the
    challenge-response step (that is the lock's / connected-room's concern).
    Returns a deny Decision (with reason) or, on success, the parsed payload.
    """
    parsed = parse_token(token)
    if parsed is None:
        return StaticResult(Decision.deny(DenyReason.MALFORMED), None)

    # Signature over the exact received payload bytes. Any tamper to the payload
    # segment (or a forged signature) fails here.
    if not _signature_ok(property_pub, parsed.payload_bytes, parsed.signature):
        return StaticResult(Decision.deny(DenyReason.FORGED_SIGNATURE), None)

    payload = parsed.payload
    key_id = str(payload.get("key_id"))

    # Structural sanity (a tampered-but-resigned payload with wrong types).
    required = ("property_id", "room_ids", "valid_from", "valid_until", "device_pub")
    if any(field not in payload for field in required):
        return StaticResult(Decision.deny(DenyReason.MALFORMED, key_id), None)

    if payload["property_id"] != expected_property:
        return StaticResult(Decision.deny(DenyReason.WRONG_PROPERTY, key_id), None)

    room_ids = payload["room_ids"]
    if not isinstance(room_ids, list) or int(expected_room) not in room_ids:
        return StaticResult(Decision.deny(DenyReason.WRONG_ROOM, key_id), None)

    if now < int(payload["valid_from"]):
        return StaticResult(Decision.deny(DenyReason.NOT_YET_VALID, key_id), None)
    if now > int(payload["valid_until"]):
        return StaticResult(Decision.deny(DenyReason.EXPIRED, key_id), None)

    if key_id in revoked:
        return StaticResult(Decision.deny(DenyReason.REVOKED, key_id), None)

    return StaticResult(None, payload)


def new_challenge() -> bytes:
    return os.urandom(config.CHALLENGE_NONCE_BYTES)


def device_sign(device_sk_b64: str, challenge: bytes) -> bytes:
    """Guest-phone side: sign a lock challenge with the per-key device private key."""
    device_sk = private_from_raw(_b64u_decode(device_sk_b64))
    return device_sk.sign(challenge)
