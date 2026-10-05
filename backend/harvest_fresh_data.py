"""
harvest_fresh_data.py — PhishGuard AI
=====================================
Stage fresh, real, currently-ACTIVE phishing DOMAINS (bare, clean) as a training
source, and reserve a disjoint holdout for an honest new-domain-recall measurement.

WHY: the model's two remaining limitations are (1) ~9.7% model-only false
positives on legit URLs and (2) weak recall on *clean bare-domain* phishing
(no path, no @, no IP, valid TLD) — a genuinely new domain that only "looks"
phishing lexically. The fix for (2) is more fresh, real phishing data, not more
rules. This harvester turns a live feed of currently-active phishing domains into
a vetted training source.

SOURCES (one domain OR url per line; '#' comments and blanks ignored):
    data/raw/phishing-domains-ACTIVE.txt      Phishing.Database ACTIVE feed
    data/raw/extra_phishing_*.txt             drop-in zone for user-supplied feeds

A domain is KEPT only if it is:
    * NOVEL  — its registrable root is not already in our phishing set, AND
    * CLEAN  — root is not in the legit set, not a curated trusted root, and not
               a shared shortener / free-host root (NOISE_ROOTS, mixed ownership).

The kept roots are split (seeded, deterministic) into:
    data/processed/fresh_phishing.csv   TRAIN source  (url=http://<root>, type=phishing)
    data/processed/fresh_holdout.csv    HELD OUT of training (measures new-domain recall)

Re-runnable: drop more feed files into data/raw/ and run again. Never touches any
model artifact — staging only.

Run from backend/ :
    python harvest_fresh_data.py
"""
import glob
import os
import random

import pandas as pd

from url_augment import registrable_domain
from config import TRUSTED_ROOTS

# Shortener / free-host roots shared by thousands of unrelated sites — a single
# "root => phishing" signal is unreliable for them. Kept in sync with
# train_ml_strong.py A5(b); the trainer re-applies this drop authoritatively, so
# this copy only keeps the staged file and the reported "usable" count honest.
NOISE_ROOTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.ly", "tny.im",
    "clck.ru", "bl.ink", "shorte.st", "adf.ly",
    "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "wix.com",
    "000webhostapp.com", "github.io", "gitlab.io", "glitch.me", "herokuapp.com",
    "web.app", "firebaseapp.com", "netlify.app", "vercel.app", "pages.dev",
    "repl.co", "surge.sh", "neocities.org", "sites.google.com", "forms.gle",
    "s3.amazonaws.com", "storage.googleapis.com", "azurewebsites.net",
    "r2.dev", "workers.dev", "onrender.com", "duckdns.org", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com",
}

RAW_DIR       = "../data/raw"
PROC_DIR      = "../data/processed"
BASE_DATASET  = os.path.join(PROC_DIR, "final_dataset.csv")
FRESH_OUT     = os.path.join(PROC_DIR, "fresh_phishing.csv")
HOLDOUT_OUT   = os.path.join(PROC_DIR, "fresh_holdout.csv")

PRIMARY_FEED  = os.path.join(RAW_DIR, "phishing-domains-ACTIVE.txt")
EXTRA_GLOB    = os.path.join(RAW_DIR, "extra_phishing_*.txt")

N_HOLDOUT     = 5_000     # reserved out of training for the before/after recall probe
SEED          = 42


def _load_feed_lines(path):
    out = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for ln in f:
            ln = ln.strip().lower()
            if not ln or ln.startswith("#") or "." not in ln:
                continue
            out.append(ln)
    return out


def main():
    # ── 1. Collect raw feed entries (domains and/or urls) ─────────────────────
    sources = []
    if os.path.exists(PRIMARY_FEED):
        sources.append(PRIMARY_FEED)
    sources.extend(sorted(glob.glob(EXTRA_GLOB)))
    if not sources:
        raise SystemExit(
            f"No feed files found. Expected {PRIMARY_FEED} or {EXTRA_GLOB}.\n"
            f"Drop a file of phishing domains/urls (one per line) into {RAW_DIR}/ "
            f"named extra_phishing_<name>.txt and re-run."
        )

    print("Feed sources:")
    raw_entries = []
    for s in sources:
        lines = _load_feed_lines(s)
        print(f"  {s}  ->  {len(lines):,} lines")
        raw_entries.extend(lines)

    # Normalise every entry (domain or url) to its registrable root.
    fresh_roots = set()
    for e in raw_entries:
        r = registrable_domain(e)
        if r and "." in r:
            fresh_roots.add(r)
    print(f"\nUnique registrable roots in feeds : {len(fresh_roots):,}")

    # ── 2. Load our existing phishing + legit roots ───────────────────────────
    print(f"Loading existing dataset ({BASE_DATASET}) — parsing urls, ~1-2 min...")
    df = pd.read_csv(BASE_DATASET).dropna(subset=["url"])
    ph_roots = set(df[df["type"] == "phishing"]["url"].astype(str).map(registrable_domain))
    lg_roots = set(df[df["type"] == "legitimate"]["url"].astype(str).map(registrable_domain))
    print(f"  existing phishing roots : {len(ph_roots):,}")
    print(f"  existing legit roots    : {len(lg_roots):,}")

    # ── 3. Keep only NOVEL + CLEAN roots ──────────────────────────────────────
    novel   = fresh_roots - ph_roots
    usable  = novel - lg_roots - set(TRUSTED_ROOTS) - NOISE_ROOTS
    print(f"\n  NOVEL (not already phishing)         : {len(novel):,}")
    print(f"  dropped: collide with legit roots    : {len(novel & lg_roots):,}")
    print(f"  dropped: trusted-root allowlist      : {len(novel & set(TRUSTED_ROOTS)):,}")
    print(f"  dropped: shortener/free-host roots   : {len(novel & NOISE_ROOTS):,}")
    print(f"  USABLE new phishing roots            : {len(usable):,}")

    if not usable:
        raise SystemExit("No usable new roots after filtering — nothing staged.")

    # ── 4. Deterministic split: holdout (never trained on) vs training source ──
    roots = sorted(usable)
    rng = random.Random(SEED)
    rng.shuffle(roots)
    n_hold = min(N_HOLDOUT, len(roots) // 5)   # never reserve more than 20%
    holdout = roots[:n_hold]
    train   = roots[n_hold:]

    def _write(path, root_list):
        pd.DataFrame(
            {"url": [f"http://{r}" for r in root_list], "type": "phishing"}
        ).to_csv(path, index=False)

    _write(FRESH_OUT, train)
    _write(HOLDOUT_OUT, holdout)

    print(f"\n[OK] staged training source : {FRESH_OUT}  ({len(train):,} domains)")
    print(f"[OK] staged holdout (unseen) : {HOLDOUT_OUT}  ({len(holdout):,} domains)")
    print("\nNext:")
    print("  1. python fresh_recall_probe.py            # baseline recall on holdout (v3.2b)")
    print("  2. (retrain) python train_ml_strong.py     # now consumes fresh_phishing.csv")
    print("  3. python fresh_recall_probe.py            # new-model recall on same holdout")
    print("  4. python fp_sweep.py                      # FP gate: must stay <= 9.70%")


if __name__ == "__main__":
    main()
