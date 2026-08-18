"""Run every bench and (re)write results/*.json + summary.json.

Usage:  python -m bench.run_all
"""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

import cryptography

from staykey import __version__ as staykey_version

from . import concurrency, latency, lifecycle_bench, scope, security

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def _meta() -> dict:
    return {
        "measured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "staykey": staykey_version,
        "platform": platform.platform(),
        "data": "100% synthetic, seeded (STAYKEY_SEED=42); simulated lock (no real BLE/NFC hardware)",
    }


def _write(name: str, payload: dict) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"meta": _meta(), **payload}
    (RESULTS_DIR / f"{name}.json").write_text(json.dumps(payload, indent=2) + "\n")
    print(f"  wrote results/{name}.json")


def main() -> None:
    print("Running StayKey benches (all numbers measured from real runs)...")

    print("- security (adversarial suite)")
    sec = security.run()
    _write("security", sec)

    print("- connected-room scope")
    scp = scope.run()
    _write("scope", scp)

    print("- concurrency / no-double-book")
    conc = concurrency.run()
    _write("concurrency", conc)

    print("- lifecycle correctness")
    life = lifecycle_bench.run()
    _write("lifecycle", life)

    print("- latency (offline verify + issuance)")
    lat = latency.run()
    _write("latency", lat)

    summary = {
        "meta": _meta(),
        "security": {
            "adversarial_attempts": sec["adversarial_attempts"],
            "adversarial_denied": sec["adversarial_denied"],
            "unauthorized_unlocks": sec["unauthorized_unlocks"],
            "access_precision": sec["access_precision"],
            "access_recall": sec["access_recall"],
            "adversarial_categories": sec["adversarial_categories"],
        },
        "connected_room": {
            "cross_scope_attempts": scp["cross_scope_attempts"],
            "cross_scope_leaks": scp["cross_scope_leaks"],
            "legit_accepted": f'{scp["legit_accepted"]}/{scp["legit_commands"]}',
        },
        "no_double_book": {
            "single_room_race": scp_none(conc["single_room_race"]),
            "double_booked_total": conc["double_booked_total"],
        },
        "lifecycle_all_correct": life["all_correct"],
        "latency": {
            "offline_verify_p50_ms": lat["offline_verify"]["p50_ms"],
            "offline_verify_p95_ms": lat["offline_verify"]["p95_ms"],
            "offline_verify_throughput_per_sec": lat["offline_verify"]["throughput_verifications_per_sec"],
            "key_issuance_p95_ms": lat["key_issuance"]["p95_ms"],
        },
    }
    RESULTS_DIR.joinpath("summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("  wrote results/summary.json")
    print("\nHeadline:")
    print(f"  unauthorized unlocks : {sec['unauthorized_unlocks']} / {sec['adversarial_attempts']} adversarial")
    print(f"  access precision/recall: {sec['access_precision']}/{sec['access_recall']}")
    print(f"  cross-room leaks     : {scp['cross_scope_leaks']} / {scp['cross_scope_attempts']}")
    print(f"  double-booked        : {conc['double_booked_total']}")
    print(f"  offline verify p50/p95: {lat['offline_verify']['p50_ms']}/{lat['offline_verify']['p95_ms']} ms")
    print(f"  verify throughput     : {lat['offline_verify']['throughput_verifications_per_sec']}/s")
    print(f"  key issuance p95      : {lat['key_issuance']['p95_ms']} ms")


def scp_none(single: dict) -> dict:
    return {
        "threads": single["threads"],
        "successes": single["successes"],
        "assignments_for_room": single["assignments_for_room"],
    }


if __name__ == "__main__":
    main()
