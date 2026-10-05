"""
model_stress_test.py — PhishGuard AI
=====================================
Answers, with numbers, four questions:

  1. Does the TRAINED MODEL work on its own (rules OFF)?
  2. False positives: does it flag genuinely-SAFE sites as phishing?
     (esp. hyphenated / wordy legit domains)
  3. False negatives: does clean-looking phishing sneak through as SAFE?
  4. Rules-first vs model-first: where do the hardcoded rules HELP,
     and where do they HURT (cause a false positive the model would not)?

Every URL below is NOT in trusted_roots, so nothing is short-circuited by
the allowlist. Section 1-3 call the MODEL DIRECTLY (rules bypassed).
Section 4 compares model-only vs the full rule pipeline.

Run from backend/ :
    python model_stress_test.py
"""

import re

import predict_ml_only as P
from features import extract_features
from config import stack_features


# ── pure model, no rules whatsoever ────────────────────────────────────────
def model_only(url: str) -> float:
    text_url = re.sub(r"^https?://", "", url)
    Xc = P.char_vec.transform([text_url])
    Xw = P.word_vec.transform([text_url])
    Xn = P.scaler.transform([extract_features(url)])
    X = stack_features(Xc, Xw, Xn)
    return float(P.model.predict_proba(X)[0][1])


# ── labelled test set (none of these are in the allowlist) ──────────────────
# label 0 = legitimate, 1 = phishing
A_CLEAN_LEGIT = [   # ordinary real sites, plain names
    "http://byjus.com", "http://unacademy.com", "http://zerodha.com",
    "http://policybazaar.com", "http://lenskart.com", "http://bookmyshow.com",
    "http://zomato.com/bangalore", "http://practo.com/doctors",
    "http://canarabank.com", "http://yesbank.in", "http://1mg.com",
    "http://cars24.com", "http://hotstar.com", "http://freshworks.com",
]
B_TRICKY_LEGIT = [  # REAL legit sites that LOOK risky (hyphens / long / words)
    "http://t-mobile.com", "http://coca-cola.com", "http://mercedes-benz.com",
    "http://e-verify.gov", "http://data-flair.training",
    "http://idfcfirstbank.com", "http://union-bank-of-india.co.in",
    "http://my-gov-services-portal.in", "http://secure-banking-login.hdfc.in",
    "http://account-help-center.zoho.com",
]
C_OBVIOUS_PHISH = [  # keyword-salad / suspicious TLD — should be caught
    "http://verify-account-security-update.com",
    "http://login-confirm-billing-alert.net",
    "http://paypal-account-verify-login.xyz",
    "http://sbi-netbanking-secure-update.info",
    "http://appleid-confirm-billing.top",
    "http://amazon-refund-claim-now.online",
    "http://update-password-now-secure.click",
    "http://free-giftcard-reward-claim.win",
]
D_CLEAN_PHISH = [   # REAL danger: phishing that looks like a normal safe domain
    "http://accountsverify.com",         # no hyphen, no keyword split
    "http://securelogin.co",             # short, benign-looking
    "http://mybankportal.in",            # plausible, plain
    "http://docs-share.com",             # single hyphen, innocuous
    "http://invoice2024.net",            # looks administrative
    "http://cloudfile.store",            # generic
    "http://portal-access.io",           # techy, plausible
    "http://update-center.app",          # sounds like a real service
]


def run(bucket, label, name):
    print(f"\n{name}")
    print("-" * 66)
    wrong = []
    for u in bucket:
        p = model_only(u)
        pred = 1 if p > 0.5 else 0
        mark = "ok " if pred == label else "XX "
        if pred != label:
            wrong.append((u, p))
        verdict = "PHISHING" if pred else "SAFE"
        print(f"  {mark}{p:>6.3f}  {verdict:<9} {u}")
    return wrong


def main():
    print("=" * 66)
    print("SECTIONS 1-3 : TRAINED MODEL ONLY  (all rules & allowlist OFF)")
    print("=" * 66)

    fp_a = run(A_CLEAN_LEGIT, 0, "A. Plain legit sites  (want SAFE)")
    fp_b = run(B_TRICKY_LEGIT, 0, "B. Legit-but-scary sites: hyphens/words  (want SAFE)")
    fn_c = run(C_OBVIOUS_PHISH, 1, "C. Obvious phishing  (want PHISHING)")
    fn_d = run(D_CLEAN_PHISH, 1, "D. Clean-looking phishing  (want PHISHING)")

    legit_total = len(A_CLEAN_LEGIT) + len(B_TRICKY_LEGIT)
    phish_total = len(C_OBVIOUS_PHISH) + len(D_CLEAN_PHISH)
    fp = len(fp_a) + len(fp_b)
    fn = len(fn_c) + len(fn_d)

    print("\n" + "=" * 66)
    print("CONFUSION SUMMARY  (model only, no rules)")
    print("=" * 66)
    print(f"  Legit sites    : {legit_total:>2}   false positives (flagged phishing): {fp}")
    print(f"  Phishing sites : {phish_total:>2}   false negatives (missed, called safe): {fn}")
    acc = (legit_total - fp + phish_total - fn) / (legit_total + phish_total)
    print(f"  Overall model-only accuracy on this set: {acc*100:.1f}%")
    if fp_b:
        print(f"\n  ! Hyphen/word FALSE POSITIVES ({len(fp_b)}): legit sites the model wrongly flagged")
        for u, p in fp_b:
            print(f"      {p:.3f}  {u}")
    if fn_d:
        print(f"\n  ! Clean-phish FALSE NEGATIVES ({len(fn_d)}): phishing the model let through")
        for u, p in fn_d:
            print(f"      {p:.3f}  {u}")

    # ── Section 4: does rule ORDER help or hurt? ────────────────────────────
    print("\n" + "=" * 66)
    print("SECTION 4 : RULES-FIRST vs MODEL-FIRST  (model-only  vs  full pipeline)")
    print("=" * 66)
    order_cases = [
        ("@-trick, model might clear it",  "http://banklogin.com@evil-collect.tk/steal"),
        ("raw IP host",                     "http://198.51.100.23/paypal/login"),
        ("legit site, but '@' in a query",  "http://mystore.in/contact?email=help@mystore.in"),
        ("legit site, '@' in path text",    "http://notes.example.in/read/user@handle"),
    ]
    print(f"\n  {'MODEL-ONLY':<22}{'FULL PIPELINE':<22}CASE")
    print("  " + "-" * 62)
    for desc, u in order_cases:
        mp = model_only(u)
        m_verdict = f"{'PHISH' if mp>0.5 else 'SAFE'} ({mp:.2f})"
        pred, prob, reason = P.predict_ml(u)
        rule = "RULE" if reason else "model"
        p_verdict = f"{'PHISH' if pred else 'SAFE'} ({prob:.2f}) [{rule}]"
        print(f"  {m_verdict:<22}{p_verdict:<22}{desc}")
        print(f"  {'':<44}{u}")
    print("\n  Row 1 (banklogin.com@evil...): the credential-hiding '@' sits in the")
    print("  AUTHORITY, so the structural RULE fires with certainty (0.999) — this")
    print("  is why structural rules run BEFORE the model. Row 2 (raw IP) likewise.")
    print("  Rows 3-4: the '@' is in the query / path, NOT the authority. Since the")
    print("  fix (features.py feat 11 is authority-scoped), the RULE no longer fires")
    print("  here — the tag reads [model], not [RULE]. Any PHISH verdict now is the")
    print("  model's own soft score on an unknown domain (tunable), not a forced,")
    print("  unrecoverable structural false positive as it was before the fix.")


if __name__ == "__main__":
    main()
