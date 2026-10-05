"""
probe_model.py — characterize what the TRAINED MODEL actually does on
non-allowlisted, non-structural URLs (pure Tier 2). No rules involved.
"""
import re
import predict_ml_only as P
from features import extract_features
from config import stack_features


def model_prob(url: str) -> float:
    text_url = re.sub(r"^https?://", "", url)
    Xc = P.char_vec.transform([text_url])
    Xw = P.word_vec.transform([text_url])
    Xn = P.scaler.transform([extract_features(url)])
    X = stack_features(Xc, Xw, Xn)
    return float(P.model.predict_proba(X)[0][1])


# All of these are LEGITIMATE real companies/sites, NOT in trusted_roots,
# NO @, NO raw IP, NO brand-spoof — so the model alone decides.
CLEAN = [
    "http://zoho.com",
    "http://freshworks.com",
    "http://ashokleyland.com",
    "http://tatamotors.com",
    "http://example.com",
    "http://mycompany.org",
    "http://ashoka.edu.in",
    "http://practo.com",
    "http://cred.club",
    "http://groww.in",
]

# Obvious phishing-style (no structural flag, so model alone decides)
PHISHY = [
    "http://paypal-account-verify-login.com",
    "http://appleid-secure-confirm.net",
    "http://sbi-netbanking-update.xyz",
    "http://amazon-billing-alert.info",
]

print(f"\n{'PROB':>7}  {'VERDICT':<9} URL   (LEGIT sites — model alone)")
print("-" * 70)
for u in CLEAN:
    p = model_prob(u)
    print(f"{p:>7.3f}  {'PHISHING' if p > 0.5 else 'SAFE':<9} {u}")

print(f"\n{'PROB':>7}  {'VERDICT':<9} URL   (PHISHY-looking — model alone)")
print("-" * 70)
for u in PHISHY:
    p = model_prob(u)
    print(f"{p:>7.3f}  {'PHISHING' if p > 0.5 else 'SAFE':<9} {u}")

# summary
clean_probs = [model_prob(u) for u in CLEAN]
fp = sum(1 for p in clean_probs if p > 0.5)
print("\n" + "=" * 70)
print(f"LEGIT sites flagged PHISHING by the model: {fp}/{len(CLEAN)}")
print(f"Model probability range on legit sites: "
      f"{min(clean_probs):.3f} – {max(clean_probs):.3f}")
print("If every legit site scores ~1.0, the model is NOT discriminating —")
print("it has learned 'unknown domain => phishing', which is the real issue.")
