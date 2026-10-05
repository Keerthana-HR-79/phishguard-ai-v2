"""
keyword_rule_probe.py — PhishGuard AI
=====================================
Operating-point analysis for the ONE remaining rule that over-flags legit hosts:
the keyword bump (W_KEYWORD=+1.5, fires when model prob >= KEYWORD_MIN_PROB AND
the URL contains any phishing keyword).

Question this analysis answered, with evidence, before rules.json was changed:
  Raising KEYWORD_MIN_PROB (then 0.40) reduces legit false positives (good)
  but may drop borderline real phishing that leaned on the +1.5 to cross the
  SUSPICIOUS line (bad). What is the net trade at 0.45 / 0.50 / 0.55 / 0.60?
  Outcome: shipped at 0.55 (v2.9). The sweep still marks the current shipped
  value (imported from config) so this probe never drifts from serving.

Only URLs with a keyword AND model prob in [0.40, 0.60) can change verdict when
we sweep KEYWORD_MIN_PROB across that range — everything else is identical at
every setting (prob<0.40 => flag never fired; prob>=0.60 => flag fires at every
candidate <=0.60; no keyword => unaffected). So the delta is fully captured here.

Faithfulness: we reproduce the REAL 4-gate serving ladder by reusing main.py's
own helpers + predict_ml_only's model/allowlist/override, so this cannot diverge
from production. The only thing stubbed is the two live NETWORK bumps (domain
age <30d -> +1.0 ; no valid SSL -> +0.5), set to "no bump":
  * for PHISHING this is CONSERVATIVE — it denies phishing any network help, so
    measured recall loss is an OVER-estimate (real recall loss <= what we print);
  * for LEGIT it is realistic (legit sites overwhelmingly have valid SSL and are
    not <30 days old), so the FP-reduction benefit is not inflated.
The real local blocklist bump (+4.0) IS applied (offline, deterministic).

Run from backend/ :
    ./venv/Scripts/python.exe keyword_rule_probe.py
"""
import re
import sys
import numpy as np
import pandas as pd
from urllib.parse import urlparse

from features import extract_features
import predict_ml_only as P            # loads model + artifacts once
import main as M                        # loads local blocklist once; gate helpers
from config import (
    TRUSTED_ROOTS, strip_www, BRANDS, KEYWORDS,
    ML_SAFE_THRESHOLD, ML_DECISION_THRESHOLD,
    W_BRAND, W_TYPO, W_SUBDOMAIN, W_IP, W_PHISHTANK, W_KEYWORD,
    DAMPENER_THRESHOLD, T_PHISHING, T_SUSPICIOUS,
    KEYWORD_MIN_PROB, stack_features,
)

KW_SET  = set(KEYWORDS)
# Sweep the KEYWORD_MIN_PROB operating points. The shipped value (config, 0.55)
# is always included and marked, so this probe can't drift from what serving uses.
SWEEP   = sorted({0.40, 0.45, 0.50, 0.55, 0.60, KEYWORD_MIN_PROB})
SEED    = 42
N_PER_SRC = 4000                              # sample size per source

FINAL = "../data/processed/final_dataset.csv"
ADV   = "../data/processed/adversarial_phishing.csv"
LEGIT = "../data/processed/legit_urls.csv"


# ── build the evaluation sample ────────────────────────────────────────────────
def _sample(path, want_type, n):
    df = pd.read_csv(path, usecols=["url", "type"]).dropna(subset=["url"])
    df = df[df["type"] == want_type]
    if len(df) > n:
        df = df.sample(n, random_state=SEED)
    return df["url"].astype(str).tolist()

print("loading samples ...")
phish = _sample(FINAL, "phishing", N_PER_SRC) + _sample(ADV, "phishing", N_PER_SRC)
legit = _sample(LEGIT, "legitimate", N_PER_SRC) + _sample(FINAL, "legitimate", N_PER_SRC)
print(f"  phishing sample: {len(phish):,}")
print(f"  legit    sample: {len(legit):,}")


# ── batch model scoring (identical to serving invariant) ───────────────────────
def _batch(urls):
    norm  = [M._normalize_url(u) for u in urls]
    feats = [extract_features(u) for u in norm]
    text  = [re.sub(r"^https?://", "", u) for u in norm]
    Xc = P.char_vec.transform(text)
    Xw = P.word_vec.transform(text)
    Xn = P.scaler.transform(np.array(feats))
    X  = stack_features(Xc, Xw, Xn)
    probs = P.model.predict_proba(X)[:, 1]
    return norm, feats, probs


def _root(u):
    host = strip_www(urlparse(u if u.startswith("http") else "http://" + u)
                     .netloc.split("@")[-1].split(":")[0])
    return P._extract_root_domain(host)


def serving_result(u, feats, prob, kmp):
    """Reproduce main.py's 4-gate verdict for one URL at a candidate
    KEYWORD_MIN_PROB (`kmp`). Network bumps (age/ssl) stubbed to no-bump."""
    # Gate 1: localhost / trusted-root allowlist
    if "localhost" in u or "127.0.0.1" in u:
        return "SAFE"
    if _root(u) in TRUSTED_ROOTS:
        return "SAFE"
    # Gate 2: absolute overrides (@ / raw IP / corroborated brand-spoof)
    if feats[10] or feats[11] or (feats[8] and (feats[9] or feats[16] or feats[20] or feats[21])):
        return "PHISHING"
    pred = int(prob > ML_DECISION_THRESHOLD)
    domain = M.extract_domain(u)
    brand = any(b in domain and not M.is_legit_brand_domain(domain, b) for b in BRANDS)
    typo  = M.check_typo(domain)[0]
    sub   = M.check_subdomain(u)[0]
    # Gate 3: confident-safe fast path
    if pred == 0 and prob < ML_SAFE_THRESHOLD and not (typo or sub or brand):
        return "SAFE"
    # Gate 4: full heuristic
    keyword = (prob >= kmp and any(k in u.lower() for k in KW_SET))
    ip      = bool(re.search(r"\d+\.\d+\.\d+\.\d+", u))
    phish_known = M.check_blocklist(u)          # real local blocklist (offline)
    score = prob * 3
    if brand:       score += W_BRAND
    if typo:        score += W_TYPO
    if sub:         score += W_SUBDOMAIN
    if ip:          score += W_IP
    if keyword:     score += W_KEYWORD
    if phish_known: score += W_PHISHTANK
    # network bumps (age<30 -> +1 ; no ssl -> +0.5) stubbed to no-bump
    if prob < DAMPENER_THRESHOLD:
        score *= 0.5
    if score > T_PHISHING:      return "PHISHING"
    if score >= T_SUSPICIOUS:   return "SUSPICIOUS"
    return "SAFE"


print("scoring phishing ...")
p_norm, p_feats, p_prob = _batch(phish)
print("scoring legit ...")
l_norm, l_feats, l_prob = _batch(legit)


def _flagged_rate(norm, feats, prob, kmp):
    flags = [serving_result(u, f, pr, kmp) != "SAFE"
             for u, f, pr in zip(norm, feats, prob)]
    return float(np.mean(flags)) * 100, flags


# ── sweep ───────────────────────────────────────────────────────────────────────
print("\n" + "=" * 66)
print("  KEYWORD_MIN_PROB sweep  (full 4-gate serving, network bumps stubbed)")
print("=" * 66)
print(f"  {'KMP':>5}   {'phish recall%':>14}   {'legit FP%':>11}")
print("  " + "-" * 40)
base_recall = base_fp = None
recall_flags = {}
fp_flags = {}
for kmp in SWEEP:
    rc, rf = _flagged_rate(p_norm, p_feats, p_prob, kmp)
    fp, ff = _flagged_rate(l_norm, l_feats, l_prob, kmp)
    recall_flags[kmp] = rf
    fp_flags[kmp] = ff
    if base_recall is None:
        base_recall, base_fp = rc, fp
    tags = []
    if kmp == 0.40:                 tags.append("baseline (pre-v2.9)")
    if kmp == KEYWORD_MIN_PROB:     tags.append("current shipped")
    marker = ("  <- " + ", ".join(tags)) if tags else ""
    print(f"  {kmp:>5.2f}   {rc:>13.2f}%   {fp:>10.2f}%{marker}")

print("  " + "-" * 40)
print(f"  vs baseline (0.40, pre-v2.9):  ", end="")
for kmp in SWEEP[1:]:
    d_rc = (np.mean(recall_flags[kmp]) - np.mean(recall_flags[0.40])) * 100
    d_fp = (np.mean(fp_flags[kmp]) - np.mean(fp_flags[0.40])) * 100
    print(f"\n     KMP {kmp:.2f}: recall {d_rc:+.2f} pt , FP {d_fp:+.2f} pt", end="")
print()


# ── affected-set anatomy (the only URLs that can change) ────────────────────────
def _affected(norm, feats, prob):
    idx = [i for i, (u, pr) in enumerate(zip(norm, prob))
           if 0.40 <= pr < 0.60 and any(k in u.lower() for k in KW_SET)]
    return idx

pa = _affected(p_norm, p_feats, p_prob)
la = _affected(l_norm, l_feats, l_prob)
print("\n" + "=" * 66)
print("  AFFECTED SET  (keyword present AND model prob in [0.40, 0.60))")
print("=" * 66)
print(f"  phishing affected: {len(pa):,} / {len(p_norm):,}  ({100*len(pa)/len(p_norm):.2f}%)")
print(f"  legit    affected: {len(la):,} / {len(l_norm):,}  ({100*len(la)/len(l_norm):.2f}%)")

# Of the affected, how many are flagged at 0.40 and flip to SAFE by 0.55?
def _flip_to_safe(idx, norm, feats, prob, kmp_hi):
    flip = 0
    for i in idx:
        was = serving_result(norm[i], feats[i], prob[i], 0.40) != "SAFE"
        now = serving_result(norm[i], feats[i], prob[i], kmp_hi) != "SAFE"
        if was and not now:
            flip += 1
    return flip

for kmp_hi in [0.50, 0.55, 0.60]:
    pf = _flip_to_safe(pa, p_norm, p_feats, p_prob, kmp_hi)
    lf = _flip_to_safe(la, l_norm, l_feats, l_prob, kmp_hi)
    print(f"\n  raising 0.40 -> {kmp_hi:.2f}:")
    print(f"     PHISHING lost (flag -> SAFE): {pf:,}   <- recall cost")
    print(f"     LEGIT    fixed (flag -> SAFE): {lf:,}   <- FP benefit")

# a few concrete phishing examples that would be lost at 0.55 (for eyeballing)
lost = [(p_prob[i], p_norm[i]) for i in pa
        if (serving_result(p_norm[i], p_feats[i], p_prob[i], 0.40) != "SAFE"
            and serving_result(p_norm[i], p_feats[i], p_prob[i], 0.55) == "SAFE")]
lost.sort(reverse=True)
if lost:
    print(f"\n  sample phishing that 0.55 would DOWNGRADE to SAFE "
          f"({len(lost)} total, top by prob):")
    for pr, u in lost[:12]:
        print(f"     {pr:.4f}  {u[:80]}")
else:
    print("\n  no phishing in the sample is downgraded to SAFE at 0.55.")
