"""
parent_path_probe.py — regression probe for the reported class of bug:
  a legit PARENT domain scores SAFE, but appending a deep, keyword-stacked PATH
  tips it to PHISHING/SUSPICIOUS. The registrable HOST is the identity; path
  shape must not flip a legit host's verdict.

byjus.com is on the trusted_roots allowlist, so it can't demonstrate the MODEL's
behaviour — this probe deliberately uses legit domains that are NOT allowlisted,
so it measures the model itself (rules bypassed), which is where the fix has to
land (train-time deep-path decorrelation in url_augment.add_path).

Run:  ./venv/Scripts/python.exe parent_path_probe.py
Pass = 0 flips (no legit host goes bare-SAFE -> deep-path-over-threshold).
"""
import re
import predict_ml_only as P
from features import extract_features
from config import ML_DECISION_THRESHOLD as THR
from config import stack_features


def model_only(url: str) -> float:
    """Model-only phishing probability, rebuilding X exactly like serving."""
    t = re.sub(r"^https?://", "", url)
    Xc = P.char_vec.transform([t]); Xw = P.word_vec.transform([t])
    Xn = P.scaler.transform([extract_features(url)])
    return float(P.model.predict_proba(stack_features(Xc, Xw, Xn))[0][1])


# Real legit domains deliberately NOT on the trusted_roots allowlist, so the
# model (not the allowlist) decides. If any of these ship on the allowlist later,
# swap in other un-allowlisted legit hosts.
DOMAINS = ["tutorialspoint.com", "indeed.com", "naukri.com", "practo.com",
           "unacademy.com", "vedantu.com", "toppr.com", "shiksha.com",
           "collegedunia.com"]

# Escalating path shapes: bare -> normal -> deep-normal -> deep keyword-stack.
# The last one is the worst case (7 stacked security words) that used to flip.
SUFFIXES = ["", "/courses", "/user/profile/settings/account",
            "/login/verify/account/secure/update/confirm/billing"]
LABELS = ["bare", "normal-path", "deep-normal", "deep-kw-stack"]


def main():
    print(f"decision threshold = {THR}   (>{THR} => model calls PHISHING)\n")
    print(f"{'domain':<20}" + "".join(f"{l:>18}" for l in LABELS))
    print("-" * 92)
    flips = []
    for d in DOMAINS:
        row = [model_only("https://" + d + suf) for suf in SUFFIXES]
        flip = row[0] <= THR and any(r > THR for r in row[1:])
        if flip:
            flips.append(d)
        print(f"{d:<20}" + "".join(f"{r:>18.4f}" for r in row)
              + ("  <-- FLIP" if flip else ""))
    print("-" * 92)
    worst = max(model_only("https://" + d + SUFFIXES[3]) for d in DOMAINS)
    print(f"\nparent-SAFE-but-path-PHISHING flips: {len(flips)}/{len(DOMAINS)}",
          flips or "(none)")
    print(f"worst deep-kw-stack prob across all: {worst:.4f}  "
          f"({'FLIP-RISK' if worst > THR else 'still SAFE'})")
    if flips:
        print("\nFAIL — a legit host's verdict still flips on path shape. The "
              "model is keying on the path, not the host; strengthen deep-path "
              "decorrelation in url_augment.add_path and retrain.")
    else:
        print("\nPASS — every legit host stays SAFE at the model level "
              "regardless of path depth/keyword-stacking. The host decides.")


if __name__ == "__main__":
    main()
