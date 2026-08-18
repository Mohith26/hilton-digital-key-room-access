"""Latency bench: offline-verify p50/p95 + throughput, and key-issuance p95.

All measured IN-PROCESS (direct function calls, no HTTP socket), so numbers reflect
the pure cryptographic verification / issuance work, not network overhead.

* offline_verify = LockVerifier.finish_unlock: 2x Ed25519 verify (property sig over
  payload + device sig over challenge) plus the window/room/property/revocation and
  anti-replay checks. Challenges are pre-registered and responses pre-signed OUTSIDE
  the timed region, so only the lock's verification path is measured.
* key_issuance = credential.issue_credential: per-key device keypair generation +
  canonical serialization + Ed25519 property signature (excludes the DB insert).
"""

from __future__ import annotations

import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from staykey import credential

from . import adversarial as A

VERIFY_N = 5000
VERIFY_WARMUP = 300
ISSUE_N = 2000
ISSUE_WARMUP = 200


def _pct(sorted_ms: list[float], p: float) -> float:
    if not sorted_ms:
        return 0.0
    k = max(0, min(len(sorted_ms) - 1, int(round(p * (len(sorted_ms) - 1)))))
    return sorted_ms[k]


def _summ(samples_ms: list[float]) -> dict:
    s = sorted(samples_ms)
    return {
        "n": len(s),
        "p50_ms": round(_pct(s, 0.50), 4),
        "p95_ms": round(_pct(s, 0.95), 4),
        "p99_ms": round(_pct(s, 0.99), 4),
        "mean_ms": round(sum(s) / len(s), 4),
        "min_ms": round(s[0], 4),
        "max_ms": round(s[-1], 4),
    }


def _bench_offline_verify() -> dict:
    scn = A.build_scenario()
    lock = A.make_lock(scn)
    total = VERIFY_N + VERIFY_WARMUP

    # Pre-build (token, challenge, response) triples OUTSIDE the timed region.
    triples = []
    for _ in range(total):
        key = credential.issue_credential(
            property_sk=scn.property_sk, guest_id="g", stay_id="s",
            property_id=A.PROPERTY_ID, room_ids=[A.TARGET_ROOM],
            valid_from=A.NOW - 3600, valid_until=A.NOW + 3600, issued_at=A.NOW - 3600,
        )
        challenge = lock.begin_unlock(A.NOW)
        response = credential.device_sign(key.device_sk_b64, challenge)
        triples.append((key.token, challenge, response))

    samples: list[float] = []
    wall_start = None
    for i, (token, challenge, response) in enumerate(triples):
        if i == VERIFY_WARMUP:
            wall_start = time.perf_counter()
        t0 = time.perf_counter_ns()
        dec = lock.finish_unlock(token=token, challenge=challenge, response=response, now=A.NOW)
        t1 = time.perf_counter_ns()
        assert dec.unlocked, "verify bench must unlock legit keys"
        if i >= VERIFY_WARMUP:
            samples.append((t1 - t0) / 1e6)
    wall_end = time.perf_counter()

    out = _summ(samples)
    elapsed = wall_end - wall_start
    out["throughput_verifications_per_sec"] = round(len(samples) / elapsed, 1)
    out["method"] = "in-process finish_unlock (2x Ed25519 verify + checks); challenges pre-registered, responses pre-signed outside timing"
    return out


def _bench_issuance() -> dict:
    property_sk = Ed25519PrivateKey.generate()
    total = ISSUE_N + ISSUE_WARMUP
    samples: list[float] = []
    for i in range(total):
        t0 = time.perf_counter_ns()
        credential.issue_credential(
            property_sk=property_sk, guest_id="g", stay_id="s",
            property_id=A.PROPERTY_ID, room_ids=[A.TARGET_ROOM],
            valid_from=A.NOW, valid_until=A.NOW + 3600, issued_at=A.NOW,
        )
        t1 = time.perf_counter_ns()
        if i >= ISSUE_WARMUP:
            samples.append((t1 - t0) / 1e6)
    out = _summ(samples)
    out["method"] = "in-process credential.issue_credential (device keygen + Ed25519 sign); excludes DB insert"
    return out


def run() -> dict:
    return {
        "offline_verify": _bench_offline_verify(),
        "key_issuance": _bench_issuance(),
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2))
