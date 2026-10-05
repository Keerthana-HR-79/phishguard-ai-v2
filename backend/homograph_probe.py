"""
homograph_probe.py — PhishGuard AI
===================================
Validates the v3.1 IDN / homograph + typosquat handling added to features.py:

  * punycode (xn--) hosts are decoded and de-confused so a look-alike brand
    (e.g. "pаypal" with a Cyrillic 'а', registered as xn--pypal-4ve.com)
    matches the real brand via the skeleton — feat 8 (brand_spoof) fires.
  * feat 20 = punycode label present, feat 21 = non-ASCII host after decode.
  * pure-ASCII typosquats (digit/letter swaps) still caught by the existing
    normalization, and stay UNaffected by the skeleton (skeleton == identity).
  * real brand roots and plain legit hosts are NOT flagged (control group).

Each row prints the raw model score, feats 7/8/9/20/21, and the full
predict_ml() verdict (structural rule vs model).

Run from backend/ :
    python homograph_probe.py
"""

import re

import predict_ml_only as P
from features import extract_features
from config import stack_features


def model_only(url: str) -> float:
    text_url = re.sub(r"^https?://", "", url)
    Xc = P.char_vec.transform([text_url])
    Xw = P.word_vec.transform([text_url])
    Xn = P.scaler.transform([extract_features(url)])
    X = stack_features(Xc, Xw, Xn)   # shared FEATURE_WEIGHTS — matches training + serving
    return float(P.model.predict_proba(X)[0][1])


# label 1 = should be caught (phishing), 0 = should NOT be flagged (legit)
CASES = [
    # ── IDN / homograph brand spoofs (punycode form) ──  want PHISHING
    ("xn--pypal-4ve.com",        1, "paypal, Cyrillic a  (punycode)"),
    ("xn--80ak6aa92e.com",       1, "apple, all-Cyrillic  (punycode)"),
    ("xn--goole-2nd.com",        1, "google-ish  (punycode)"),
    ("secure-xn--microsft-jbb.com", 1, "microsoft homograph + keyword"),

    # ── ASCII typosquats (no IDN) ──  want PHISHING
    ("paypa1-login.com",         1, "paypal digit-1 swap + keyword"),
    ("arnazon-account.com",      1, "amazon rn->m + keyword"),
    ("g00gle-verify.com",        1, "google 0-swap + keyword"),
    ("faceb00k-security.net",    1, "facebook 0-swap + keyword"),
    ("microsofr-support.xyz",    1, "microsoft t->r + keyword + bad TLD"),

    # ── control: real brand roots ──  want SAFE (domain == brand)
    ("paypal.com",               0, "real paypal root"),
    ("google.com",               0, "real google root"),
    ("apple.com",                0, "real apple root"),

    # ── control: plain legit, no brand ──  want SAFE
    ("byjus.com",                0, "plain legit"),
    ("zerodha.com",              0, "plain legit"),
]


def main():
    print("=" * 78)
    print("IDN / HOMOGRAPH + TYPOSQUAT PROBE  (model score + feats + predict_ml)")
    print("=" * 78)
    print(f"  {'score':>6} {'f7':>4} {'f8':>3} {'f9':>3} {'f20':>4} {'f21':>4}  "
          f"{'predict_ml':<22} case")
    print("  " + "-" * 74)

    caught = 0
    total = len(CASES)
    for host, label, desc in CASES:
        url = "http://" + host
        f = extract_features(url)
        score = model_only(url)
        pred, prob, reason = P.predict_ml(url)
        rule = "RULE" if reason else "model"
        verdict = f"{'PHISH' if pred else 'SAFE':<5} {prob:.2f} [{rule}]"
        ok = (pred == label)
        if ok:
            caught += 1
        mark = "ok " if ok else "XX "
        print(f"  {mark}{score:>5.3f} {f[7]:>4.2f} {f[8]:>3} {f[9]:>3} "
              f"{f[20]:>4} {f[21]:>4}  {verdict:<22} {desc}")
        if not ok:
            print(f"      ^ WANTED {'PHISH' if label else 'SAFE'}  ({host})")

    print("\n  " + "-" * 74)
    print(f"  predict_ml correct on {caught}/{total} cases")
    print("\n  Read: f8=1 means the brand-spoof flag fired (skeleton match); for a")
    print("  punycode host f20/f21=1 too. A real brand ROOT has f7=1 (name present)")
    print("  but f8=0 (domain == brand), so it is NOT flagged — that's the control.")


if __name__ == "__main__":
    main()
