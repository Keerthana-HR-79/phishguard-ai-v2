"""
byjus_pathfix_probe.py — regression probe for the reported false positive:
  https://byjus.com  was SAFE, but byjus.com with a deep / many-slash path
  crept toward PHISHING.

Two independent fixes are checked here:
  1) MODEL level — deep, keyword-stacked paths on a legit host must stay SAFE.
     Fixed by deep-path decorrelation in url_augment.add_path (v3.2), applied to
     BOTH classes at train time so path DEPTH/keyword-stacking carries no label
     signal — only the HOST does.
  2) RUNTIME level — runs of redundant slashes must be collapsed before analysis
     (main.py._normalize_url), so byjus.com//////login can't inflate features.

This script tests (1) directly on the model (rules bypassed). Test (2) via the
live backend (it is a normalization step, not a model change):
    curl -s localhost:8000/predict_url -H "content-type: application/json" \
         -d '{"url":"https://byjus.com//////////login/verify/account"}'
"""
import re
import predict_ml_only as P
from features import extract_features
from config import ML_DECISION_THRESHOLD, stack_features

THR = ML_DECISION_THRESHOLD   # the real serving decision boundary (rules.json)


def model_only(url: str) -> float:
    """Model-only phishing probability, rebuilding X exactly like serving."""
    t = re.sub(r"^https?://", "", url)
    Xc = P.char_vec.transform([t]); Xw = P.word_vec.transform([t])
    Xn = P.scaler.transform([extract_features(url)])
    return float(P.model.predict_proba(stack_features(Xc, Xw, Xn))[0][1])


# The exact variants from the bug report, escalating in depth / keyword-stacking.
CASES = [
    "https://byjus.com",
    "https://byjus.com/home",
    "https://byjus.com/account",
    "https://byjus.com/products/item/123",
    "https://byjus.com/login/verify/account",
    "https://byjus.com/a/b/c/d/e/f/login/verify/account",   # was SUSPICIOUS 3.59
    "https://byjus.com/secure/update/confirm/billing/auth/session/token",
]

print(f"{'url':<62}{'model_prob':>12}   verdict")
print("-" * 92)
worst = 0.0
for u in CASES:
    p = model_only(u)
    worst = max(worst, p)
    print(f"{u:<62}{p:>12.4f}   {'PHISHING' if p > THR else 'SAFE'}")

print("-" * 92)
if worst <= THR:
    print(f"PASS — every byjus.com path variant stays SAFE at model level "
          f"(worst model_prob={worst:.4f} < decision threshold {THR}).")
    print("The host decides, not the path depth. Deep-path artifact is dead.")
    print("(byjus.com is also on the trusted_roots allowlist, so serving is SAFE "
          "regardless — this model-level check is defense-in-depth.)")
else:
    print(f"FAIL — a byjus.com path variant went PHISHING at model level "
          f"(worst model_prob={worst:.4f} >= decision threshold {THR}).")
    print("Deep-path decorrelation did not fully generalize to byjus; the")
    print("trusted_roots allowlist still catches byjus.com at serving time.")
