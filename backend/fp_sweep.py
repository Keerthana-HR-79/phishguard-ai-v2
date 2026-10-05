"""
fp_sweep.py — large-scale LEGIT false-positive rate, model-only (rules OFF).

Sweeps every URL in legit_urls.csv through the trained model alone (the
trusted-root allowlist and structural rules are bypassed) and counts how many
known-legit URLs the model wrongly scores as phishing (prob > threshold). This
is the metric that matters for the reported byjus-class problem: how often the
raw model flags a legitimate site. Lower is better.

Reproducible baseline for comparing model versions (v3.1 -> v3.2 etc.).
Run:
    python fp_sweep.py                       # sweep the LIVE model (cwd)
    python fp_sweep.py model_backup_v31_...  # sweep a backed-up model dir
Loading artifacts from an explicit dir lets us score two model versions on the
IDENTICAL URL set for a fair comparison.
"""
import os
import re
import sys
import pickle
import numpy as np
import pandas as pd

from features import extract_features
from config import ML_DECISION_THRESHOLD, stack_features

MODEL_DIR = sys.argv[1] if len(sys.argv) > 1 else "."
LEGIT = "../data/processed/legit_urls.csv"
THR = ML_DECISION_THRESHOLD

def _load(name):
    with open(os.path.join(MODEL_DIR, name), "rb") as f:
        return pickle.load(f)

model    = _load("model.pkl")
char_vec = _load("char_vectorizer.pkl")
word_vec = _load("word_vectorizer.pkl")
scaler   = _load("scaler.pkl")

df = pd.read_csv(LEGIT).dropna(subset=["url"])
urls = df["url"].astype(str).tolist()
n = len(urls)
print(f"Model dir: {MODEL_DIR}")
print(f"Sweeping {n:,} known-legit URLs (model-only, rules bypassed, thr={THR})...")

# Batch the vectorizers (fast); extract_features is per-URL.
text = [re.sub(r"^https?://", "", u) for u in urls]
Xc = char_vec.transform(text)
Xw = word_vec.transform(text)
Xn = scaler.transform(np.array([extract_features(u) for u in urls]))
X = stack_features(Xc, Xw, Xn)

probs = model.predict_proba(X)[:, 1]
fp_mask = probs > THR
fp = int(fp_mask.sum())
print(f"\n  Legit URLs swept      : {n:,}")
print(f"  Model false positives : {fp:,}  ({fp / n * 100:.2f}%)")
print(f"  (a legit URL scored > {THR} by the model alone)")

# Show the worst offenders so the failure mode is visible.
order = np.argsort(-probs)[:15]
print("\n  Worst 15 legit FPs (highest model prob):")
for i in order:
    if probs[i] > THR:
        print(f"    {probs[i]:.3f}  {urls[i]}")
