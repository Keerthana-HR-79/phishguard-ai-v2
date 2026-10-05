"""
operating_point.py — PhishGuard AI
==================================
Fair cross-version comparison at EQUAL false-positive rate.

A retrain that shifts the decision boundary changes BOTH the legit false-positive
rate and the phishing recall together, so comparing two models at a fixed 0.5
threshold is misleading. This script scores one model on:
  * the full legit set (legit_urls.csv)         -> false-positive rate
  * the unseen fresh holdout (fresh_holdout.csv) -> new bare-domain recall
across a range of thresholds, then reports the recall achievable at the threshold
that pins the legit FP rate to a target (default 9.70%, the permanent model-only
FP gate — the hard ceiling first set by v3.2b that no retrain may regress).

A candidate is worth shipping only if, at that same gate FP, it reaches a HIGHER
holdout recall than the model CURRENTLY SHIPPED (below). Comparing against the
shipped model — not a frozen historical number — keeps this gate honest as the
baseline moves: v3.3 beat v3.2b (24.9% -> 54.9%), v3.4 beat v3.3, v3.5 (the
leakage-free/deterministic retrain) held v3.4's equal-FP recall while lowering
FP, and the next retrain must beat v3.5 or be reverted. Model-only (rules
bypassed), identical serving weights as training.

Run from backend/ :
    python operating_point.py                      # live model (cwd)
    python operating_point.py model_backup_v33...  # a backed-up model dir
"""
import os
import re
import sys
import pickle
import numpy as np
import pandas as pd

from features import extract_features
from config import stack_features

MODEL_DIR = sys.argv[1] if len(sys.argv) > 1 else "."
LEGIT   = "../data/processed/legit_urls.csv"
HOLDOUT = "../data/processed/fresh_holdout.csv"
TARGET_FP = 0.0970          # permanent model-only FP gate (set by v3.2b, never regress)

# Recall baseline a candidate must beat = the CURRENTLY SHIPPED model measured at
# this same gate operating point. Update these two lines whenever a retrain ships.
# v3.5 (shipped): the leakage-free (M10) + deterministic (M11) retrain. At the
# threshold that pins FP <= 9.70% it reaches 61.3% fresh-holdout recall (>= v3.4's
# 61.2%) while lowering the shipped-threshold model-only FP 6.91% -> 6.23%.
SHIPPED_LABEL  = "v3.5 (shipped)"
SHIPPED_RECALL = 61.3


def _load(name):
    with open(os.path.join(MODEL_DIR, name), "rb") as f:
        return pickle.load(f)


model    = _load("model.pkl")
char_vec = _load("char_vectorizer.pkl")
word_vec = _load("word_vectorizer.pkl")
scaler   = _load("scaler.pkl")


def _scores(path):
    df = pd.read_csv(path).dropna(subset=["url"])
    urls = df["url"].astype(str).tolist()
    text = [re.sub(r"^https?://", "", u) for u in urls]
    Xc = char_vec.transform(text)
    Xw = word_vec.transform(text)
    Xn = scaler.transform(np.array([extract_features(u) for u in urls]))
    X = stack_features(Xc, Xw, Xn)
    return model.predict_proba(X)[:, 1]


print(f"Model dir: {MODEL_DIR}")
print("Scoring legit set (80k, ~2 min)...")
legit = _scores(LEGIT)
print("Scoring unseen fresh holdout (5k)...")
hold = _scores(HOLDOUT)

n_leg, n_hold = len(legit), len(hold)
print(f"  legit URLs   : {n_leg:,}")
print(f"  holdout phish: {n_hold:,}\n")

print("  thr    FP%     recall%   (legit false positives / unseen-phish caught)")
print("  " + "-" * 60)
for t in [0.30, 0.40, 0.50, 0.55, 0.60, 0.61, 0.62, 0.63, 0.64, 0.65, 0.70, 0.75, 0.80]:
    fp = float((legit > t).mean()) * 100
    rc = float((hold > t).mean()) * 100
    print(f"  {t:.2f}  {fp:6.2f}   {rc:6.1f}")

# Threshold that pins FP to the target (highest threshold with FP <= target has
# the highest recall while still satisfying the gate; scan fine grid).
grid = np.round(np.arange(0.30, 0.951, 0.005), 3)
best_t, best_rc, best_fp = None, -1.0, None
for t in grid:
    fp = float((legit > t).mean())
    if fp <= TARGET_FP:
        rc = float((hold > t).mean())
        # lowest threshold meeting the gate = highest recall meeting the gate
        best_t, best_rc, best_fp = float(t), rc * 100, fp * 100
        break

print("\n  " + "=" * 60)
print(f"  Gate target FP <= {TARGET_FP*100:.2f}%  (permanent gate, set by v3.2b)")
if best_t is not None:
    print(f"  -> threshold {best_t:.3f} gives FP {best_fp:.2f}%  and recall {best_rc:.1f}%")
    print(f"  {SHIPPED_LABEL} operating point at this gate: recall {SHIPPED_RECALL:.1f}%")
    verdict = (f"DOMINATES {SHIPPED_LABEL}" if best_rc > SHIPPED_RECALL
               else f"does NOT beat {SHIPPED_LABEL}")
    print(f"  -> candidate {verdict} at equal FP")
    print(f"     (running this on the shipped model itself reads 'does NOT beat' —")
    print(f"      it IS the baseline; a retrain must clear {SHIPPED_RECALL:.1f}% to ship.)")
else:
    print("  -> no threshold in grid pins FP at/under target (unexpected)")
