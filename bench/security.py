"""Headline security bench: run the adversarial + legit suite through the offline
lock and compute access-decision precision/recall + 0-unauthorized-unlock count."""

from __future__ import annotations

from collections import Counter

from . import adversarial as A

N_EACH = 40
N_LEGIT = 100


def run() -> dict:
    scn = A.build_scenario()
    attempts = A.build_attempts(scn, n_each=N_EACH, n_legit=N_LEGIT)
    lock = A.make_lock(scn)  # built AFTER attempts so it holds every revoked key-id

    tp = fp = fn = tn = 0
    unauthorized: list[str] = []
    by_category: Counter[str] = Counter()
    denied_by_category: Counter[str] = Counter()
    deny_reasons: Counter[str] = Counter()

    for at in attempts:
        decision = at.run(lock)
        by_category[at.category] += 1
        if at.expect_unlock:
            if decision.unlocked:
                tp += 1
            else:
                fn += 1
        else:
            if decision.unlocked:
                fp += 1
                unauthorized.append(at.category)
            else:
                tn += 1
                denied_by_category[at.category] += 1
                if decision.reason is not None:
                    deny_reasons[decision.reason.value] += 1

    n_adv = sum(1 for a in attempts if not a.expect_unlock)
    n_legit = sum(1 for a in attempts if a.expect_unlock)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0

    adversarial_categories = sorted(c for c in by_category if c != "legit")
    return {
        "total_attempts": len(attempts),
        "adversarial_attempts": n_adv,
        "adversarial_denied": n_adv - len(unauthorized),
        "unauthorized_unlocks": len(unauthorized),
        "legit_attempts": n_legit,
        "legit_unlocked": tp,
        "access_precision": round(precision, 6),
        "access_recall": round(recall, 6),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "adversarial_categories": adversarial_categories,
        "per_category_attempts": dict(by_category),
        "per_category_denied": dict(denied_by_category),
        "deny_reason_distribution": dict(deny_reasons),
        "note": "single offline LockVerifier (property HILTON-DEMO-001, room 101); "
        "tampered payloads are caught by the property-signature check (deny reason forged_signature).",
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2))
