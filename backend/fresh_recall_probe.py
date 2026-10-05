"""
fresh_recall_probe.py — PhishGuard AI
=====================================
Measures how well the CURRENT live model catches *clean bare-domain* phishing —
limitation #2 (a brand-new domain with no path, no @, no IP, valid TLD, that only
looks phishing lexically). Runs on data/processed/fresh_holdout.csv, a set of real
currently-active phishing domains that harvest_fresh_data.py deliberately kept OUT
of training, so the score is an honest generalization estimate on unseen domains.

Reports, on the bare `http://<domain>` form of each holdout domain:
  * predict_ml detection rate  — the full 3-tier serving verdict (what users get)
  * model-only detection rate  — raw calibrated XGBoost > threshold (rules bypassed)
  * the model-prob distribution — so a shift is visible even below the threshold

Run BEFORE a retrain (records the v3.2b baseline) and AFTER (the new model), on
the identical holdout, for a clean before/after comparison. Rules bypassed via the
same serving weights as training. Never modifies anything.

Run from backend/ :
    python fresh_recall_probe.py
"""
import numpy as np
import pandas as pd

import predict_ml_only as P
from homograph_probe import model_only
from config import ML_DECISION_THRESHOLD

HOLDOUT = "../data/processed/fresh_holdout.csv"
THR = ML_DECISION_THRESHOLD


def main():
    df = pd.read_csv(HOLDOUT).dropna(subset=["url"])
    urls = df["url"].astype(str).tolist()
    n = len(urls)
    print(f"Holdout: {n:,} real, currently-active phishing domains NOT seen in training")
    print(f"Threshold: {THR}\n")

    probs = np.array([model_only(u) for u in urls])
    ml_pred = np.array([P.predict_ml(u)[0] for u in urls])

    model_hits = int((probs > THR).sum())
    ml_hits = int((ml_pred == 1).sum())

    print("  -- detection rate on unseen bare phishing domains --")
    print(f"  predict_ml (full serving verdict) : {ml_hits:,}/{n:,}  ({ml_hits/n*100:.1f}%)")
    print(f"  model-only (raw calibrated XGB)   : {model_hits:,}/{n:,}  ({model_hits/n*100:.1f}%)")

    print("\n  -- model-prob distribution (higher = more phishing-like) --")
    for p in (10, 25, 50, 75, 90):
        print(f"    p{p:<2} : {np.percentile(probs, p):.3f}")
    print(f"    mean: {probs.mean():.3f}")
    for lo, hi in [(0.0, 0.25), (0.25, 0.5), (0.5, 0.75), (0.75, 1.01)]:
        c = int(((probs >= lo) & (probs < hi)).sum())
        print(f"    [{lo:.2f},{hi:.2f}) : {c:,}  ({c/n*100:.1f}%)")


if __name__ == "__main__":
    main()
