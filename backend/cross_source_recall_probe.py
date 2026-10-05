"""
cross_source_recall_probe.py — PhishGuard AI
============================================
HONEST cross-source recall. `fresh_recall_probe.py` measures recall on
`fresh_holdout.csv`, which was carved from the SAME Phishing.Database ACTIVE
harvest the model trained on — so its 54.9–56.7% is a *same-feed-family* number
and is very likely optimistic. This probe answers the harder question:

    How many phishing URLs does the MODEL catch when they come from a feed the
    model never trained on at all?

Independent sources (both are different feeds from Phishing.Database ACTIVE):
  * OpenPhish  (data/raw/openphish.txt)  — live community feed, pulled 2026-09-24.
  * PhishTank  (data/raw/phishtank.csv)  — larger snapshot; MAY overlap the older
    final_dataset corpus, so the novelty filter below matters most here.

Scored MODEL-ONLY (raw calibrated XGBoost via the exact training/serving invariant
`config.stack_features` / FEATURE_WEIGHTS), with the local blocklist and the trusted-root
allowlist BYPASSED. That is deliberate: OpenPhish/PhishTank URLs *are* the local
blocklist, so a full-pipeline test would trivially read ~100% and prove nothing
about the model's lexical generalization. We want the model's own opinion.

For each source we report recall at the shipped threshold (0.6) and at 0.5, on:
  * ALL entries, and
  * NOVEL-only — registrable root NOT among the training phishing roots (the true
    zero-leakage cross-source number).
We also print the model-prob distribution and two structural cuts that EXPLAIN any
gap honestly: fraction that is pathed, and fraction whose root is on the trusted
allowlist (compromised-host / shared-host phishing whose ROOT is legit — a lexical
blind spot the model cannot and should not catch from the string alone; that is the
blocklist's job). The same-feed `fresh_holdout` is re-scored in the same run as an
anchor (should reproduce ~56.7% @0.6, validating the batch scorer).

Read-only — never modifies anything. Run from backend/ :
    ./venv/Scripts/python.exe cross_source_recall_probe.py
"""
import csv
import os
import re
import sys

import numpy as np
import pandas as pd
from urllib.parse import urlparse

from features import extract_features
import predict_ml_only as P                 # model + vectorizers + scaler (loaded once)
import main as M                             # _normalize_url (mirror serving input hygiene)
from config import ML_DECISION_THRESHOLD, TRUSTED_ROOTS, strip_www, stack_features

THR = ML_DECISION_THRESHOLD                  # 0.6 (shipped)
DATA = os.path.join("..", "data")

OPENPHISH = os.path.join(DATA, "raw", "openphish.txt")
PHISHTANK = os.path.join(DATA, "raw", "phishtank.csv")
FINAL     = os.path.join(DATA, "processed", "final_dataset.csv")
FRESH_PH  = os.path.join(DATA, "processed", "fresh_phishing.csv")
ADV       = os.path.join(DATA, "processed", "adversarial_phishing.csv")
HOLDOUT   = os.path.join(DATA, "processed", "fresh_holdout.csv")

# Minimal public-suffix handling for registrable-root extraction. Only needs to be
# SELF-CONSISTENT (same function on both the training side and the test side) for
# the novelty match to be meaningful — it is not used for scoring.
_TWO_PART = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "gov.in",
    "ac.in", "co.jp", "com.br", "com.au", "co.nz", "com.cn", "co.za", "com.mx",
    "com.tr", "com.sg", "com.hk", "com.tw",
}


def registrable(u: str) -> str:
    # String-split host extraction (NOT urlparse — Python 3.12's urlsplit raises
    # on malformed bracketed hosts, and the training corpus has a few; this is
    # also faster over ~900k rows). Only needs to be self-consistent both sides.
    try:
        s = re.sub(r"^[a-z]+://", "", str(u).strip().lower())
        host = s.split("/")[0].split("?")[0].split("@")[-1].split(":")[0]
        host = strip_www(host)
        parts = [p for p in host.split(".") if p]
        if len(parts) <= 2:
            return host
        last2 = ".".join(parts[-2:])
        if last2 in _TWO_PART and len(parts) >= 3:
            return ".".join(parts[-3:])
        return last2
    except Exception:
        return ""


def is_pathed(u: str) -> bool:
    try:
        s = re.sub(r"^[a-z]+://", "", str(u).strip().lower())
        after_host = s.split("/", 1)
        has_path = len(after_host) > 1 and after_host[1].strip("/") != ""
        return has_path or ("?" in s)
    except Exception:
        return False


# ── serving-invariant batch model-only scorer (mirrors train/serve exactly) ─────
def batch_probs(urls):
    norm = [M._normalize_url(u) for u in urls]
    feats = [extract_features(u) for u in norm]
    text = [re.sub(r"^https?://", "", u) for u in norm]
    Xc = P.char_vec.transform(text)
    Xw = P.word_vec.transform(text)
    Xn = P.scaler.transform(np.array(feats))
    X = stack_features(Xc, Xw, Xn)
    return P.model.predict_proba(X)[:, 1]


# ── load the union of training PHISHING roots (for the novelty filter) ───────────
def load_training_roots():
    roots = set()
    # final_dataset is large (~63 MB) — read in chunks, keep only phishing roots.
    for chunk in pd.read_csv(FINAL, usecols=["url", "type"], chunksize=200_000):
        ph = chunk[chunk["type"] == "phishing"]["url"].dropna().astype(str)
        roots.update(registrable(u) for u in ph)
    for path in (FRESH_PH, ADV):
        df = pd.read_csv(path).dropna(subset=["url"])
        if "type" in df.columns:
            df = df[df["type"] == "phishing"]
        roots.update(registrable(u) for u in df["url"].astype(str))
    roots.discard("")
    return roots


# ── source loaders ───────────────────────────────────────────────────────────────
def load_openphish():
    out = []
    with open(OPENPHISH, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def load_phishtank():
    df = pd.read_csv(PHISHTANK, usecols=lambda c: c.strip().lower() == "url")
    col = df.columns[0]
    return df[col].dropna().astype(str).tolist()


def load_holdout():
    df = pd.read_csv(HOLDOUT).dropna(subset=["url"])
    return df["url"].astype(str).tolist()


# ── report one source ──────────────────────────────────────────────────────────
def report(name, urls, train_roots):
    urls = [u for u in urls if isinstance(u, str) and u.strip()]
    n = len(urls)
    if n == 0:
        print(f"\n{name}: no usable URLs — skipped."); return
    probs = batch_probs(urls)
    roots = [registrable(u) for u in urls]
    novel = np.array([r not in train_roots for r in roots])
    pathed = np.array([is_pathed(u) for u in urls])
    allow = np.array([r in TRUSTED_ROOTS for r in roots])

    def rec(mask, thr):
        # Serving flags a URL when prob > threshold (strict), matching
        # predict_ml / operating_point.py. Using >= here would over-count recall
        # by the mass sitting exactly on the boundary.
        m = mask & (probs > thr)
        d = int(mask.sum())
        return (int(m.sum()), d, (100.0 * m.sum() / d if d else 0.0))

    allm = np.ones(n, dtype=bool)
    print(f"\n{'='*70}\n  {name}   (N={n:,})\n{'='*70}")
    print(f"  novel roots (unseen in training)  : {int(novel.sum()):,}  ({100*novel.mean():.1f}%)")
    print(f"  pathed / has-query                : {int(pathed.sum()):,}  ({100*pathed.mean():.1f}%)")
    print(f"  root on trusted allowlist (legit) : {int(allow.sum()):,}  ({100*allow.mean():.1f}%)"
          f"   <- model cannot catch these from the root; blocklist's job")
    print(f"\n  model-only recall (rules + blocklist BYPASSED):")
    for label, mask in (("ALL   ", allm), ("NOVEL ", novel)):
        h6, d6, r6 = rec(mask, 0.60)
        h5, d5, r5 = rec(mask, 0.50)
        print(f"    {label} @0.60 : {h6:>6,}/{d6:<6,} ({r6:5.1f}%)"
              f"     @0.50 : {h5:>6,}/{d5:<6,} ({r5:5.1f}%)")
    print(f"\n  model-prob distribution (all {n:,}):")
    for p in (10, 25, 50, 75, 90):
        print(f"    p{p:<2}: {np.percentile(probs, p):.3f}", end="   ")
    print(f"\n    mean: {probs.mean():.3f}")
    return probs, novel


def main():
    print("loading training phishing roots (novelty filter) ...")
    train_roots = load_training_roots()
    print(f"  training phishing roots: {len(train_roots):,}")

    # Anchor: same-feed holdout, same scorer — should reproduce ~56.7% @0.60.
    hold = load_holdout()
    hp = batch_probs(hold)
    hn = len(hold)
    print(f"\n{'#'*70}")
    print(f"  ANCHOR — same-feed holdout (fresh_holdout.csv, N={hn:,})")
    print(f"  model-only recall @0.60 : {int((hp>0.60).sum()):,}/{hn:,} "
          f"({100*(hp>0.60).mean():.1f}%)   @0.50 : {100*(hp>0.50).mean():.1f}%")
    print(f"  (expect ~56.7% @0.60 — validates the batch scorer matches model_only)")
    print(f"{'#'*70}")

    report("OpenPhish (live, independent feed)", load_openphish(), train_roots)
    report("PhishTank (snapshot, independent feed)", load_phishtank(), train_roots)

    print(f"\n{'='*70}")
    print("  READING THE RESULT")
    print(f"{'='*70}")
    print("  * The NOVEL @0.60 column is the honest cross-source generalization number.")
    print("  * A gap vs the ~56.7% same-feed anchor is EXPECTED and is explained by the")
    print("    'pathed' + 'root on trusted allowlist' rows: compromised-host / shared-host")
    print("    phishing is a URL-lexical blind spot the model cannot get from the string —")
    print("    that is exactly what the local blocklist (D1) and refresh_feeds.py cover.")
    print("  * This probe is READ-ONLY and shares the train/serve invariant, so it can be")
    print("    re-run after any retrain for a like-for-like cross-source comparison.")


if __name__ == "__main__":
    main()
