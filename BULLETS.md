# Résumé Bullets — StayKey (filled strictly from measured results)

> Measured 2026-08-18, Python 3.12 + `cryptography` 50.0.0 (Ed25519), with
> **synthetic seeded** data and a **simulated lock (no real BLE/NFC hardware)**.
> Every number traces to `results/*.json`. Unmeasured values are the literal `___`.

## The 3 bullets (spec) — filled

- Built a **Hilton-style Digital Key system** (mobile check-in → Ed25519-signed,
  time-boxed room key → **offline door-lock verifier**) with **0 unauthorized
  unlocks across 400 adversarial attempts** (expired / not-yet-valid / wrong-room /
  wrong-property / revoked / replayed / forged / tampered / impersonation /
  malformed) — access-decision **precision/recall 1.0 / 1.0**.
  <br>_(all MEASURED: 400 adversarial denied / 400; 100 legit unlocked / 100;
  precision=recall=1.0. Honesty: **simulated lock**, no real hardware; the presented
  key is verified in-process. Tampered payloads deny via the signature check —
  reason `forged_signature`.)_

- Designed the lock to verify keys **fully offline** (property public key + synced
  revocation list, **no network / no DB at unlock time**) at **p95 0.30 ms /
  ≈3,489 verifications/sec**, with **checkout-triggered revocation** enforced across
  the key lifecycle (issue → active → revoked; revoked keys denied even inside their
  original window).
  <br>_(MEASURED: offline-verify p50 0.28 ms, p95 0.30 ms, throughput 3,488.9/s;
  lifecycle `all_correct: true`. Honesty: latency measured **in-process** (direct
  calls, 2× Ed25519 verify + checks), **not over a network socket**; offline-ness
  is proven by an import-closure test + a monkeypatched-DB/socket test.)_

- Guaranteed **0 double-assigned rooms** under concurrent booking (32-thread race →
  1 winner; 40 overlapping stays / 10 rooms → 0 shared) and scoped **Connected
  Room** controls (TV/thermostat/lights) to the active stay (**0 cross-room leaks /
  26 attempts**), verified by **45 passing tests at 91% coverage**.
  <br>_(all MEASURED: double_booked_total=0; cross_scope_leaks=0/26, legit 9/9;
  45 passed; 91% coverage on `staykey/`. Honesty: concurrency via SQLite
  `BEGIN IMMEDIATE` writer serialization; synthetic seeded data.)_

## Measured-value ledger

| Placeholder | Value | Status |
|---|---|---|
| adversarial attempts (0 unauthorized unlocks) | 400 (0 unlocked) | MEASURED |
| access precision / recall | 1.0 / 1.0 | MEASURED |
| legit unlocked | 100 / 100 | MEASURED |
| offline-verify p50 / p95 | 0.2819 / 0.3018 ms | MEASURED (in-process) |
| offline-verify throughput | 3,488.9 verifications/sec | MEASURED (in-process) |
| key-issuance p95 | 0.1466 ms | MEASURED (in-process) |
| connected-room cross-scope leaks | 0 / 26 | MEASURED |
| double-assigned rooms | 0 | MEASURED |
| tests / coverage | 45 passed / 91% | MEASURED |

## Honesty tags
- ✅ MEASURED from real runs; all numbers in `results/*.json`.
- ⚠️ **Simulated lock** — no real BLE/NFC hardware; the transport/radio is not modeled.
- ⚠️ Latency measured **in-process** (direct calls), not over an HTTP/TCP socket.
- ⚠️ Synthetic seeded data (`STAYKEY_SEED=42`); single demo property.
- ⚠️ `forged_signature` count (80) covers both the forged and tampered categories —
  a mutated payload fails the signature check identically; both are denied.
- ❌ Not a real Hilton/PMS deployment; no cloud deploy; no certified crypto stack.
