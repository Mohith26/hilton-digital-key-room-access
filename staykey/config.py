"""Central configuration constants. No magic numbers scattered through the code."""

from __future__ import annotations

import os
from pathlib import Path

# --- Key issuance model ----------------------------------------------------
# A Digital Key is short-TTL and refreshable. Its effective validity window is
# bounded by BOTH the stay window [check_in, check_out] AND a short rolling TTL:
#   valid_from  = stay.check_in
#   valid_until = min(stay.check_out, issued_at + KEY_TTL_SECONDS)
# The guest app re-fetches (refresh) before the TTL lapses. This mirrors real
# mobile-key systems that hand out short-lived credentials refreshed over the air.
KEY_TTL_SECONDS: int = 24 * 60 * 60  # 24h default rolling TTL

# --- Offline anti-replay (challenge-response) ------------------------------
# The lock issues a fresh single-use random challenge per unlock; the guest
# device signs it with the per-key device private key. A challenge expires after
# this window and is consumed on first use, defeating replay of a captured
# (challenge, response) pair.
CHALLENGE_TTL_SECONDS: int = 30
CHALLENGE_NONCE_BYTES: int = 32
CREDENTIAL_NONCE_BYTES: int = 16

# --- Crypto ----------------------------------------------------------------
# Ed25519 signature scheme (property key + per-key device key).
SIGNATURE_ALG: str = "Ed25519"

# --- Storage ---------------------------------------------------------------
_DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR: Path = Path(os.environ.get("STAYKEY_DATA_DIR", str(_DEFAULT_DATA_DIR)))
DB_PATH: Path = Path(os.environ.get("STAYKEY_DB_PATH", str(DATA_DIR / "staykey.sqlite")))
# The property's PRIVATE key lives ONLY here (gitignored) or in an env var.
PROPERTY_SK_PATH: Path = Path(
    os.environ.get("STAYKEY_PROPERTY_SK_PATH", str(DATA_DIR / "property_ed25519_sk.pem"))
)

# --- Determinism -----------------------------------------------------------
RANDOM_SEED: int = int(os.environ.get("STAYKEY_SEED", "42"))

# --- Connected Room --------------------------------------------------------
ALLOWED_DEVICES: tuple[str, ...] = ("tv", "thermostat", "lights")
