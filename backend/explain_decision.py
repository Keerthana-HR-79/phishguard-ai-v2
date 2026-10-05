"""
explain_decision.py — PhishGuard AI diagnostic
================================================
For each URL, reports WHICH layer actually made the decision:

  ALLOWLIST  → Tier 0  trusted_roots hit (hardcoded guard, forces SAFE)
  STRUCTURAL → Tier 1  @ / raw-IP / brand-spoof (hardcoded rule, forces PHISHING)
  MODEL      → Tier 2  the trained XGBoost model decided, and its raw
                        calibrated probability is shown

Run from the backend/ folder:
    python explain_decision.py
"""

import re
from urllib.parse import urlparse

from features import extract_features
from config import TRUSTED_ROOTS, strip_www
import predict_ml_only as P


def which_tier(url: str):
    """Re-run the exact tier logic from predict_ml_only, but report the tier."""
    if "localhost" in url or "127.0.0.1" in url:
        return "ALLOWLIST", 0, 0.001, "localhost"

    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    host = strip_www(parsed.netloc.split("@")[-1].split(":")[0])

    # Tier 0 — hardcoded allowlist
    root = P._extract_root_domain(host)
    if root in TRUSTED_ROOTS:
        return "ALLOWLIST", 0, 0.001, f"root '{root}' in trusted_roots"

    # Tier 1 — hardcoded structural rules
    feats = extract_features(url)
    if feats[8]:
        return "STRUCTURAL", 1, 0.999, "brand-spoof (feat 8)"
    if feats[10]:
        return "STRUCTURAL", 1, 0.999, "raw IP host (feat 10)"
    if feats[11]:
        return "STRUCTURAL", 1, 0.999, "@ trick (feat 11)"

    # Tier 2 — the TRAINED MODEL decides
    pred, prob, _ = P.predict_ml(url)
    return "MODEL", pred, prob, "trained XGBoost calibrated probability"


SAMPLES = [
    # --- Tier 0: allowlisted (hardcoded SAFE) ---
    "https://www.google.com",
    "https://onlinesbi.sbi/login",
    # --- Tier 1: structural (hardcoded PHISHING) ---
    "https://paypa1.com@secure-update.xyz",
    "http://192.168.10.5/account/login",
    "http://paypa1-login-secure.com",
    # --- Tier 2: UNKNOWN domains -> the trained MODEL must decide ---
    "http://account-verification-portal.web.app/login",
    "http://free-giftcard-claim-now.online/reward",
    "http://secure-document-share-drive.click/file",
    "http://banking-portal-update-now.website/auth",
    "http://your-invoice-download-ready.support/pdf",
    "http://daily-weather-updates-live.info/",
    "http://my-personal-travel-blog-2024.net/posts",
    "http://open-source-dev-tools-hub.io/docs",
    "http://community-recipe-sharing.kitchen/home",
    "http://local-photography-portfolio.gallery/work",
]


def main():
    counts = {"ALLOWLIST": 0, "STRUCTURAL": 0, "MODEL": 0}
    print(f"\n{'DECIDED BY':<12} {'VERDICT':<9} {'PROB':>6}  URL")
    print("-" * 78)
    for url in SAMPLES:
        tier, pred, prob, why = which_tier(url)
        counts[tier] += 1
        verdict = "PHISHING" if pred == 1 else "SAFE"
        short = url if len(url) <= 40 else url[:37] + "..."
        print(f"{tier:<12} {verdict:<9} {prob:>6.3f}  {short}")

    print("-" * 78)
    total = len(SAMPLES)
    print(f"\nOf {total} URLs:")
    print(f"  {counts['ALLOWLIST']:>2} decided by HARDCODED allowlist (Tier 0)")
    print(f"  {counts['STRUCTURAL']:>2} decided by HARDCODED structural rules (Tier 1)")
    print(f"  {counts['MODEL']:>2} decided by the TRAINED MODEL (Tier 2)")
    print()
    print("Note the MODEL rows: the probabilities are a spectrum (not 0.001/0.999).")
    print("That spectrum IS the trained XGBoost computing on inputs it has never")
    print("seen and was never given a rule for.")


if __name__ == "__main__":
    main()
