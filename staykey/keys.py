"""Property keypair management + Digital Key issuance orchestration.

The property's Ed25519 PRIVATE key signs every credential. It is generated once
and stored ONLY in a gitignored PEM file (or an env var); the PUBLIC key is what
gets provisioned into locks. Issuance ties the credential to the stay window and a
short rolling TTL, records the key server-side (public token only), and returns
the token + the per-key device private key to the guest's phone.
"""

from __future__ import annotations

import base64
import os
import sqlite3
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import config, credential, db
from .credential import IssuedKey, public_raw
from .errors import NotFoundError, ValidationError


# --------------------------------------------------------------------------
# Property keypair (private key stored only in a gitignored file / env)
# --------------------------------------------------------------------------
def load_or_create_property_key(path: Path | None = None) -> Ed25519PrivateKey:
    """Load the property private key from PEM, or generate + persist it (0600)."""
    # Env var takes precedence (12-factor; nothing written to disk).
    env_pem = os.environ.get("STAYKEY_PROPERTY_SK_PEM")
    if env_pem:
        return serialization.load_pem_private_key(env_pem.encode(), password=None)  # type: ignore[return-value]

    sk_path = Path(path or config.PROPERTY_SK_PATH)
    if sk_path.exists():
        return serialization.load_pem_private_key(sk_path.read_bytes(), password=None)  # type: ignore[return-value]

    sk = Ed25519PrivateKey.generate()
    sk_path.parent.mkdir(parents=True, exist_ok=True)
    pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    sk_path.write_bytes(pem)
    os.chmod(sk_path, 0o600)
    return sk


def property_public_raw(sk: Ed25519PrivateKey) -> bytes:
    return public_raw(sk.public_key())


def property_public_b64(sk: Ed25519PrivateKey) -> str:
    return base64.urlsafe_b64encode(property_public_raw(sk)).rstrip(b"=").decode()


# --------------------------------------------------------------------------
# Issuance
# --------------------------------------------------------------------------
def effective_window(check_in: int, check_out: int, issued_at: int) -> tuple[int, int]:
    """Credential validity: bounded by the stay AND a short rolling TTL.

    valid_from  = check_in           (before this -> not_yet_valid)
    valid_until = min(check_out, issued_at + KEY_TTL_SECONDS)
    """
    valid_from = int(check_in)
    valid_until = min(int(check_out), int(issued_at) + config.KEY_TTL_SECONDS)
    return valid_from, valid_until


def issue_for_stay(
    conn: sqlite3.Connection,
    property_sk: Ed25519PrivateKey,
    stay_id: str,
    *,
    now: int,
) -> IssuedKey:
    """Issue (or refresh) a Digital Key for a stay's currently assigned room."""
    stay = db.get_stay(conn, stay_id)
    if stay is None:
        raise NotFoundError(f"stay {stay_id} not found")
    if stay["room_id"] is None:
        raise ValidationError("stay has no assigned room; assign a room first")

    valid_from, valid_until = effective_window(stay["check_in"], stay["check_out"], now)
    if valid_until <= valid_from:
        raise ValidationError("stay window already elapsed; cannot issue key")

    issued = credential.issue_credential(
        property_sk=property_sk,
        guest_id=stay["guest_id"],
        stay_id=stay_id,
        property_id=stay["property_id"],
        room_ids=[int(stay["room_id"])],
        valid_from=valid_from,
        valid_until=valid_until,
        issued_at=int(now),
        key_id=uuid.uuid4().hex,
    )
    db.add_key(
        conn,
        {
            "key_id": issued.key_id,
            "stay_id": stay_id,
            "room_id": int(stay["room_id"]),
            "issued_at": int(now),
            "valid_from": valid_from,
            "valid_until": valid_until,
            "token": issued.token,
        },
    )
    return issued
