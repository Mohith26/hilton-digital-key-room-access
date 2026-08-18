"""Headline security test: 0 unauthorized unlocks across the adversarial suite;
legit in-window keys unlock; access precision/recall = 1.0."""

from __future__ import annotations

from bench import adversarial as A
from bench import security


def test_zero_unauthorized_unlocks_and_perfect_pr():
    result = security.run()
    assert result["unauthorized_unlocks"] == 0
    assert result["adversarial_denied"] == result["adversarial_attempts"]
    assert result["access_precision"] == 1.0
    assert result["access_recall"] == 1.0
    assert result["legit_unlocked"] == result["legit_attempts"]


def test_every_adversarial_category_present_and_denied():
    result = security.run()
    expected = {
        "expired", "not_yet_valid", "wrong_room", "wrong_property",
        "forged_signature", "tampered_payload", "revoked", "replayed",
        "impersonation", "malformed",
    }
    assert set(result["adversarial_categories"]) == expected
    # every adversarial attempt in every category was denied
    for cat in expected:
        assert result["per_category_denied"][cat] == result["per_category_attempts"][cat]


def test_each_category_denies_with_a_reason():
    """Directly assert each single adversarial key denies (small, explicit suite)."""
    scn = A.build_scenario()
    attempts = A.build_attempts(scn, n_each=1, n_legit=1)
    lock = A.make_lock(scn)
    for at in attempts:
        dec = at.run(lock)
        if at.expect_unlock:
            assert dec.unlocked, f"legit key should unlock, got {dec.reason}"
        else:
            assert not dec.unlocked, f"{at.category} must be denied but unlocked"
            assert dec.reason is not None
