# StayKey — Measured Results

**Date measured:** 2026-08-18
**Engine:** Python 3.12.13, `cryptography` **50.0.0** (Ed25519), FastAPI 0.141, SQLite.
**Platform:** macOS (arm64). **Data:** 100% **synthetic**, seeded (`STAYKEY_SEED=42`).

Every number below comes from a real run. Machine-readable values are committed
under `results/*.json`; anything not measured is written as a literal `___`.

> **Simulated lock.** There is **no real BLE/NFC hardware** — the door lock is an
> in-process `LockVerifier`. The cryptography, offline decision logic, revocation,
> and anti-replay are real; the radio link is simulated. Latency is measured
> **in-process** (direct function calls), not over an HTTP/TCP socket.

---

## How to reproduce (exact commands)

```bash
# 0. setup
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

# 1. full test suite (reservation / offline purity / security / lifecycle / scope / api)
pytest -q                                  # -> 45 passed
pytest -q --cov=staykey --cov-report=term-missing   # -> 91% coverage

# 2. end-to-end OFFLINE unlock + adversarial deny demo (no server, no network)
python -m scripts.demo_offline_unlock

# 3. run every benchmark and (re)write results/*.json + summary
python -m bench.run_all

#    individual benches:
python -m bench.security          # adversarial suite -> 0 unauthorized unlocks
python -m bench.scope             # connected-room cross-scope leaks
python -m bench.concurrency       # no-double-book under threads
python -m bench.lifecycle_bench   # issue->active->revoked + boundaries
python -m bench.latency           # offline-verify p50/p95 + throughput, issuance p95

# 4. run the live API + a real over-the-socket flow
uvicorn staykey.api:app --port 8000
curl -s localhost:8000/health
```

---

## 1. Security — adversarial suite (headline) — `results/security.json`

A single **offline** `LockVerifier` (property `HILTON-DEMO-001`, room 101) is
presented **500** key presentations: **100 legitimate** in-window keys and **400
adversarial** keys across 10 categories. Each presentation runs the full
challenge-response.

| Metric | Value |
|---|---|
| Adversarial attempts denied | **400 / 400 = 100%** |
| **Unauthorized unlocks** | **0** |
| Legitimate keys unlocked | **100 / 100** |
| Access-decision **precision** | **1.0** (TP=100, FP=0) |
| Access-decision **recall** | **1.0** (TP=100, FN=0) |
| Confusion matrix | TP=100 · FP=0 · FN=0 · TN=400 |

**Adversarial categories (40 each, all denied):**

| Category | What it is | Deny reason returned |
|---|---|---|
| expired | `now > valid_until` | `expired` |
| not_yet_valid | `now < valid_from` (before check-in) | `not_yet_valid` |
| wrong_room | key for another room | `wrong_room` |
| wrong_property | key for another property (real signer) | `wrong_property` |
| forged_signature | payload signed by an attacker key | `forged_signature` |
| tampered_payload | valid key's window extended, original sig kept | `forged_signature` |
| revoked | valid key whose id is on the lock's revocation list | `revoked` |
| replayed | a captured (challenge, response) resent | `replayed` |
| impersonation | valid token, attacker lacks the device key | `bad_response` |
| malformed | garbage token | `malformed` |

> **Honest note:** *tampered_payload* and *forged_signature* both surface as deny
> reason `forged_signature` (80 total) — a mutated payload fails the property
> signature exactly like a forged one. That is the correct cryptographic outcome;
> both are counted as denied, in distinct attack categories.

## 2. Connected-Room scope — `results/scope.json`

Three checked-in stays in three rooms; commands (`tv`/`thermostat`/`lights`) fired
through the real `ConnectedRoomAuthorizer`.

| Metric | Value |
|---|---|
| Legitimate commands accepted | **9 / 9** (each guest → own room, all devices) |
| Cross-scope attempts | **26** |
| **Cross-scope command leaks** | **0** |

Cross-scope attempts rejected: cross-room (guest A → room B), impersonation (A's
token without A's device key), unsupported command (`open_safe`), and post-checkout
control of a freed room. Deny reasons: `wrong_room`, `bad_command`, `revoked`,
`bad_response`.

## 3. No double-booking — `results/concurrency.json`

Overlap uses half-open intervals `[check_in, check_out)`; the check-and-insert runs
inside `BEGIN IMMEDIATE`, so concurrent writers serialize.

| Scenario | Result |
|---|---|
| 32 threads race for the **same room + overlapping window** | **1 success, 31 rejected, 1 assignment** (0 double-booked) |
| 40 overlapping stays compete for **10 rooms** | **10 assigned, 10 distinct rooms, 0 shared** |
| **Double-booked total** | **0** |

## 4. Key lifecycle — `results/lifecycle.json`

All checks `true` (`all_correct: true`):

| Check | Result |
|---|---|
| Issued key unlocks in window | ✅ |
| Before check-in → `not_yet_valid` | ✅ |
| After check-out window → `expired` | ✅ |
| **Checkout revokes** → denied within original window (`revoked`) | ✅ |
| Room-change re-keys → old key denied, new key opens new room | ✅ |
| New key at old room → denied (`wrong_room`) | ✅ |

Short-TTL model: `valid_until = min(check_out, issued_at + 24h)`; refresh issues a
new key without revoking the old (rolling window) — verified in
`tests/test_lifecycle_revocation.py`.

## 5. Latency — `results/latency.json`

Measured **in-process** (no HTTP socket).

| Metric | Value |
|---|---|
| Offline-verify **p50** | **0.2819 ms** |
| Offline-verify **p95** | **0.3018 ms** |
| Offline-verify **p99** | **0.3863 ms** |
| Offline-verify **throughput** | **3,488.9 verifications/sec** |
| Key-issuance **p50 / p95** | **0.1384 / 0.1466 ms** |

- **offline_verify** = `LockVerifier.finish_unlock` over 5,000 iterations (300
  warm-up excluded): **2× Ed25519 verify** (property signature over payload +
  device signature over challenge) plus window/room/property/revocation and
  anti-replay checks. Challenges are pre-registered and responses pre-signed
  **outside** the timed region, so only the lock's verification path is measured.
- **key_issuance** = `credential.issue_credential` over 2,000 iterations: per-key
  device keypair generation + canonical serialization + Ed25519 signature (excludes
  the DB insert).

## 6. Tests / coverage

```
pytest -q                       -> 45 passed
pytest --cov=staykey            -> 91% coverage on staykey/
```

Per-module coverage highlights: `lock.py` **100%**, `credential.py` 95%,
`db.py`/`errors.py`/`models.py`/`config.py` 100%, `api.py` 81%.

---

## Honest limitations / notes

- **Simulated lock — no real BLE/NFC hardware.** The radio/transport is not
  modeled; the crypto, offline decision, revocation sync, and anti-replay are.
- **Synthetic seeded data** — no real guests or PII.
- **Latency is in-process** (direct calls), not over a network socket; it reflects
  the pure cryptographic verify/issue work.
- **Anti-replay is challenge-response**: the lock issues a fresh single-use nonce
  and the phone signs it with the per-key device key. Replaying a captured
  `(challenge, response)` fails because the challenge is consumed/expired. This
  mirrors real mobile-key systems (credential binds a device key; per-unlock
  challenge-response) but is a from-scratch implementation, not a certified one.
- **Single demo property** (`HILTON-DEMO-001`); multi-property key rotation and an
  audit log are Should-have (v2), not built.
- **Concurrency** relies on SQLite `BEGIN IMMEDIATE` writer serialization — correct
  for this workload, not tuned for high-throughput multi-node deployment.
- Not built (out of scope): real hardware, a guest/lock web UI, BLE session keys,
  rate limiting, multi-region infra.
