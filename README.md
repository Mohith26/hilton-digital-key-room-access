# StayKey — Hilton-style Digital Key

A **Digital Key** system reproducing Hilton's signature product end-to-end:
**reservation → mobile check-in → a cryptographically-signed, time-boxed,
OFFLINE-verifiable room key → a door lock that verifies it with no network → a
checkout that revokes it → Connected-Room controls scoped to the active stay.**
Benchmarked for security (**0 unauthorized unlocks** across an adversarial suite),
offline-verify latency/throughput, overlap-safe room assignment, and full key
lifecycle.

> Built for a **Hilton Technology 2027 Intern (Software Engineering & Cyber;
> Connected Room / Mobile)** target. A hotel door lock has **no internet**, so the
> key must be verifiable **offline** from a signature + validity window + a
> periodically-synced revocation list — a genuinely interesting distributed-security
> design with hard, testable properties.

> ### Read me first — scope & honesty
> - **Simulated lock.** There is **no real BLE/NFC hardware**; the "lock" is an
>   in-process `LockVerifier`. The cryptography, offline decision logic, revocation,
>   and anti-replay are real; the radio link is not.
> - **100% synthetic, seeded data** (`STAYKEY_SEED=42`). No real guests or PII.
> - **Latency is measured in-process** (direct calls), not over an HTTP socket.
> - Full methodology + every measured number: **[RESULTS.md](RESULTS.md)**; raw
>   JSON in `results/`; résumé bullets in **[BULLETS.md](BULLETS.md)**.

## How a key is verified offline

Issuance signs a compact credential with the **property's Ed25519 private key** and
binds it to a **per-key device key** the guest's phone holds:

```
token = b64url(payload).b64url(property_signature)
payload = { key_id, guest_id, stay_id, property_id, room_ids,
            valid_from, valid_until, issued_at, nonce, device_pub }
```

Unlock is a **challenge-response** so a captured transmission can't be replayed:

```
  phone                              door lock  (holds ONLY property_pub + revocation list)
    │   POST begin_unlock ─────────────▶  generate fresh single-use challenge (nonce)
    │  ◀───────────────── challenge ────
    │   sign(challenge, device_sk)
    │   token + challenge + response ──▶  verify OFFLINE, no network / no DB:
    │                                     1. property signature over payload  (else forged/tampered)
    │                                     2. property_id + room_id match this lock
    │                                     3. valid_from ≤ now ≤ valid_until      (else not-yet/expired)
    │                                     4. key_id ∉ revocation list           (else revoked)
    │                                     5. challenge issued, unused, unexpired (else replayed/unknown)
    │                                     6. response is device_pub's sig of challenge (else bad_response)
    │  ◀──────────── UNLOCK / DENY(reason)
```

The lock never contacts the backend at unlock time. Revoked key-ids arrive out of
band via `sync_revocations()` (a simulated periodic OTA sync); the decision uses
only the lock's local snapshot. This is **proven** two ways in
`tests/test_offline_purity.py`: (1) the import closure of `staykey.lock` +
`staykey.credential` contains no DB/socket/HTTP/framework module, and (2) the
verifier decides correctly with `sqlite3.connect` and `socket.socket` monkeypatched
to raise.

## Tech stack
Python 3.12 · **cryptography** (Ed25519 sign/verify) · FastAPI + uvicorn · pydantic ·
SQLite (reservations) · pytest + pytest-cov. Free/local, CPU-only, no external
services or keys.

## Layout
```
staykey/
  config.py        constants (TTL, challenge window, seed, paths)
  errors.py        Decision + DenyReason enum (every deny is explained)
  credential.py    PURE core: issue / parse / verify signed key + device challenge-response
  antireplay.py    PURE single-use challenge store (shared by lock + connected room)
  lock.py          OFFLINE LockVerifier: property pubkey + revocation list only
  db.py            SQLite store (guests/rooms/stays/assignments/keys/revocations)
  reservation.py   overlap-safe room assignment (BEGIN IMMEDIATE, half-open intervals)
  keys.py          property keypair (gitignored PEM) + issuance orchestration
  lifecycle.py     checkout / room-change -> revoke ; refresh (rolling TTL)
  connectedroom.py per-stay device control scope enforcement (tv/thermostat/lights)
  app_state.py     wiring: property key, DB, simulated per-room lock registry
  api.py           FastAPI: reserve / checkin / refresh / checkout / room-change /
                   lock challenge+unlock / room control ; consistent {ok,data,error}
bench/             adversarial suite, scope, concurrency, lifecycle, latency, run_all
tests/             45 tests: reservation, concurrency, offline purity, security suite,
                   lifecycle/revocation, connected-room scope, anti-replay, credential, API
scripts/demo_offline_unlock.py   end-to-end offline unlock/deny demo (no server)
results/*.json     committed measured numbers
```

## Quickstart

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

pytest -q                              # 45 passed
python -m scripts.demo_offline_unlock  # offline unlock + adversarial denials
python -m bench.run_all                # (re)write results/*.json + print headline

# run the API
uvicorn staykey.api:app --port 8000
curl -s localhost:8000/health
open http://localhost:8000/docs        # OpenAPI UI
```

### API

| Endpoint | Purpose |
|---|---|
| `POST /rooms` · `POST /guests` | seed inventory |
| `POST /reservations` | create stay + **overlap-safe** room assignment |
| `POST /checkin/{stay_id}` | issue Digital Key → `{token, device_sk_b64, window}` |
| `POST /keys/{stay_id}/refresh` | rolling short-TTL re-issue |
| `POST /checkout/{stay_id}` | **revoke** the stay's key(s) → sync to lock |
| `POST /stays/{stay_id}/room-change` | reassign + revoke old + issue new |
| `POST /lock/{room_id}/challenge` · `/unlock` | simulated offline presentation |
| `POST /room/{room_id}/challenge` · `/control` | Connected-Room device command |
| `GET /revocations` · `/health` | revocation list / status |

## Measured results (see [RESULTS.md](RESULTS.md))

| Metric | Value |
|---|---|
| Unauthorized unlocks | **0 / 400 adversarial** (expired · not-yet-valid · wrong-room · wrong-property · forged · tampered · revoked · replayed · impersonation · malformed) |
| Access-decision precision / recall | **1.0 / 1.0** (100 legit unlock, 400 adversarial deny) |
| Connected-Room cross-scope leaks | **0 / 26** (9/9 legit accepted) |
| Double-assigned rooms | **0** (32-thread race → 1 winner; 40 overlapping stays / 10 rooms → 0 shared) |
| Offline-verify latency | **p50 0.28 ms · p95 0.30 ms**, **≈3,489 verifications/sec** (in-process) |
| Key-issuance | **p95 0.15 ms** (in-process) |
| Tests / coverage | **45 passed · 91% coverage** on `staykey/` |

## Security notes
- The property **private key never leaves** `data/` (gitignored PEM, 0600) or an env
  var; only the **public** key is provisioned into locks. No secret is committed.
- The guest's **device private key** never reaches the lock — the lock only sees the
  device *public* key inside the signed payload.
- Every rejection carries a machine-readable `DenyReason`; the API validates all
  input and returns a consistent `{ok, data, error}` envelope.
