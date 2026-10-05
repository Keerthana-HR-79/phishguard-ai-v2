"""
Locks the end-to-end predict_ml() behaviour and the model's decision surface —
the invariants that past bugs violated and that a future retrain must not break:

  * trusted roots and localhost are never flagged (false-positive guard),
  * the deterministic structural overrides (raw IP / '@' credential trick) fire,
  * the full 14-case homograph + typosquat + control set stays 14/14,
  * the byjus deep-path artifact stays dead AT THE MODEL LEVEL (below the
    decision threshold) even without the trusted-root allowlist catching it.

These reuse the exact CASES and serving-weight model_only() helper from
homograph_probe.py, so the suite and the probe can never silently diverge.
"""
import pytest

import predict_ml_only as P
from homograph_probe import CASES, model_only
from config import ML_DECISION_THRESHOLD


# ── False-positive guard: trusted + localhost always SAFE ────────────────────
@pytest.mark.parametrize("url", [
    "https://google.com",
    "https://byjus.com",
    "https://byjus.com/login/verify/account/secure/update",  # deep path, still trusted
    "http://localhost:8000/dashboard",
    "http://127.0.0.1/admin",
])
def test_trusted_and_localhost_never_flagged(url):
    pred, prob, _ = P.predict_ml(url)
    assert pred == 0


def test_trusted_root_reason_and_probability():
    pred, prob, reason = P.predict_ml("https://google.com")
    assert pred == 0
    assert reason == "Globally trusted domain"
    assert prob < 0.05


# ── Deterministic structural overrides always fire ──────────────────────────
@pytest.mark.parametrize("url", [
    "http://45.12.67.89/login",                 # raw IP (feat 10)
    "http://amazon.com@evil-verify.ru/login",   # credential '@' (feat 11)
])
def test_structural_overrides_force_phishing(url):
    pred, prob, reason = P.predict_ml(url)
    assert pred == 1
    assert reason and "Critical" in reason


# ── The full homograph + typosquat + control set stays 14/14 ────────────────
@pytest.mark.parametrize("host,label,desc", CASES, ids=[c[2] for c in CASES])
def test_homograph_and_typosquat_cases(host, label, desc):
    pred, prob, reason = P.predict_ml("http://" + host)
    assert pred == label, f"{host} ({desc}) -> pred {pred}, wanted {label}"


# ── byjus deep-path artifact is dead at the MODEL level (defense in depth) ──
# The trusted-root allowlist already catches byjus.com, but the underlying
# model must independently keep these below the decision boundary — that is the
# train-time path-decorrelation invariant, and the layer that protects every
# legit host NOT on the allowlist. Worst observed in v3.2b was ~0.453.
@pytest.mark.parametrize("url", [
    "https://byjus.com/login/verify/account/secure/update",
    "https://byjus.com/home",
    "https://byjus.com/products/item/1042",
    "https://byjus.com/a/b/login/verify/account",
])
def test_byjus_deep_paths_stay_below_threshold_model_only(url):
    score = model_only(url)
    assert score < ML_DECISION_THRESHOLD, f"{url} model score {score:.4f} >= threshold"
