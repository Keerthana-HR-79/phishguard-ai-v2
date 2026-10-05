"""
predict_ml_only.py — PhishGuard AI model scorer (model v3.5)
URL phishing predictor: loopback guard + trusted-root guard + structural
overrides + calibrated ML. Host checks are parsed-host based (not substring),
so a keyword in the path can't spoof the loopback/IP short-circuits.
"""

import os
import re
import pickle

from features import extract_features
from config import (
    TRUSTED_ROOTS, strip_www, ML_DECISION_THRESHOLD,
    parse_host, host_is_ip, host_is_loopback, stack_features,
)

# Load model artifacts. Anchored on THIS module's directory, not the process
# CWD, so importing predict_ml (directly or via main.py) works no matter where
# the interpreter was launched — the same robustness fix applied to the
# blocklist feed path in main.py.
_MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
def _load_pkl(name: str):
    with open(os.path.join(_MODEL_DIR, name), "rb") as fh:
        return pickle.load(fh)

model    = _load_pkl("model.pkl")
char_vec = _load_pkl("char_vectorizer.pkl")
word_vec = _load_pkl("word_vectorizer.pkl")
scaler   = _load_pkl("scaler.pkl")

# False-positive guard — NOT the detector.
# The ML model + heuristics judge every site. TRUSTED_ROOTS (from rules.json)
# is a short allowlist of major, high-traffic domains that exists only so the
# model can never *wrongly* flag them (a false positive on google.com would
# destroy user trust). Everything not on the list is decided by the model.
_TWO_PART_TLDS = {"co", "ac", "gov", "net", "org", "edu", "com"}


def _extract_root_domain(host: str) -> str:
    host = strip_www(host)
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in _TWO_PART_TLDS:
        return ".".join(parts[-3:]).lower()
    return ".".join(parts[-2:]).lower() if len(parts) > 1 else parts[0].lower()


def predict_ml(url: str) -> tuple[int, float, str | None]:
    """
    Returns (prediction, probability, override_reason).
    """
    host = parse_host(url)

    # Localhost / loopback dev environment — matched on the PARSED HOST only.
    # (A substring test on the whole URL let any link force SAFE just by
    #  appending '/localhost' or '/127.0.0.1', bypassing every gate below.)
    if host_is_loopback(host):
        return 0, 0.001, "Localhost dev environment"

    # Tier 0: trusted-root fast path (false-positive guard)
    if _extract_root_domain(host) in TRUSTED_ROOTS:
        return 0, 0.001, "Globally trusted domain"

    # Tier 1: structural checks — checked before ML.
    # A raw-IP HOST and the credential-hiding "@" in the authority (feat 11)
    # are unambiguous, so each forces the verdict on its own. The raw-IP test
    # keys on the actual host being an IP literal (v4 or v6) — NOT on a dotted
    # quad appearing anywhere in the URL — so a '/v1.2.3.4/' version path can no
    # longer force-flag a legit host (feat 10 still feeds the model). A
    # brand-spoof fuzzy match (feat 8) is NOT enough alone — a legit name can
    # resemble a brand — so it forces the verdict only when CORROBORATED by a
    # phishing keyword (feat 9), a suspicious TLD (feat 16), or an IDN/homograph
    # host (feat 20/21). Uncorroborated, it falls through to the soft model
    # score in Tier 2 instead of an unrecoverable 0.999 (D4).
    feats = extract_features(url)
    brand_spoof_corroborated = feats[8] and (feats[9] or feats[16] or feats[20] or feats[21])
    if host_is_ip(host) or feats[11] or brand_spoof_corroborated:
        return 1, 0.999, "Critical: Structural security risk detected"

    # Tier 2: calibrated ML inference
    text_url = re.sub(r"^https?://", "", url)
    Xc = char_vec.transform([text_url])
    Xw = word_vec.transform([text_url])
    Xn = scaler.transform([feats])
    X = stack_features(Xc, Xw, Xn)   # FEATURE_WEIGHTS applied in one shared place

    prob = float(model.predict_proba(X)[0][1])
    pred = int(prob > ML_DECISION_THRESHOLD)

    return pred, prob, None
