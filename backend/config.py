"""
config.py — central rule/config loader for PhishGuard AI.

All tunable rule data (brand list, phishing keywords, suspicious TLDs,
trusted-root allowlist, scoring weights, thresholds, network timeouts) lives
in rules.json. This module loads it once and exposes typed constants so the
rest of the code never hardcodes a list or a magic number.

Change behaviour by editing rules.json — no Python edits required.
(Exception: brands/keywords/suspicious_tlds feed the model's features, so
 re-run train_ml_strong.py after changing those three.)
"""

import ipaddress
import json
import os
import re
from urllib.parse import urlsplit

_CFG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")

with open(_CFG_PATH, "r", encoding="utf-8") as _f:
    CONFIG = json.load(_f)

# ── Rule lists ─────────────────────────────────────────────────────────────────
BRANDS          = [b.lower() for b in CONFIG["brands"]]
KEYWORDS        = [k.lower() for k in CONFIG["keywords"]]
SUSPICIOUS_TLDS = [t.lower().lstrip(".") for t in CONFIG["suspicious_tlds"]]
TRUSTED_ROOTS   = {d.lower() for d in CONFIG["trusted_roots"]}

# Third-party-content commons (user-subdomain site/blog hosts). A SUBSET of
# TRUSTED_ROOTS whose trust belongs to the platform, not the tenant — so an
# exact known-phishing blocklist match on a URL here overrides the allowlist
# (main.py Gate 2b). Must stay a subset of TRUSTED_ROOTS, or the override could
# never fire (a shared-host URL only reaches Gate 2b as a "Globally trusted
# domain" SAFE). Assert it so a future rules.json edit can't silently break it.
SHARED_HOSTING_ROOTS = {d.lower() for d in CONFIG.get("shared_hosting_roots", [])}
_orphan_shared = SHARED_HOSTING_ROOTS - TRUSTED_ROOTS
assert not _orphan_shared, (
    f"shared_hosting_roots must be a subset of trusted_roots; "
    f"not in trusted_roots: {sorted(_orphan_shared)}"
)

# ── Scoring weights & thresholds ────────────────────────────────────────────────
_S = CONFIG["scoring"]
ML_SAFE_THRESHOLD  = float(_S["ML_SAFE_THRESHOLD"])
# Decision boundary for the calibrated model (prob > this ⇒ phishing). Tunable
# in rules.json without a retrain; defaults to 0.5 if absent. Used by predict_ml.
ML_DECISION_THRESHOLD = float(_S.get("ML_DECISION_THRESHOLD", 0.5))
W_BRAND            = float(_S["W_BRAND"])
W_TYPO             = float(_S["W_TYPO"])
W_SUBDOMAIN        = float(_S["W_SUBDOMAIN"])
W_IP               = float(_S["W_IP"])
# LEGACY: the blocklist is now a DECISIVE gate in main.py (Gate 2b), not a
# weighted signal, so serving no longer reads W_PHISHTANK. It remains only so
# keyword_rule_probe.py can model the pre-v3.0 weighted ladder for comparison.
W_PHISHTANK        = float(_S["W_PHISHTANK"])
W_NEW_DOMAIN       = float(_S["W_NEW_DOMAIN"])
W_NO_SSL           = float(_S["W_NO_SSL"])
W_KEYWORD          = float(_S["W_KEYWORD"])
KEYWORD_MIN_PROB   = float(_S["KEYWORD_MIN_PROB"])
DAMPENER_THRESHOLD = float(_S["DAMPENER_THRESHOLD"])
T_PHISHING         = float(_S["T_PHISHING"])
T_SUSPICIOUS       = float(_S["T_SUSPICIOUS"])

# ── Network timeouts / cache ────────────────────────────────────────────────────
_N = CONFIG.get("network", {})
WHOIS_TIMEOUT_SEC     = float(_N.get("WHOIS_TIMEOUT_SEC", 4))
SSL_TIMEOUT_SEC       = float(_N.get("SSL_TIMEOUT_SEC", 5))
META_CACHE_TTL_SEC    = float(_N.get("META_CACHE_TTL_SEC", 900))

# ── Serving limits (input hardening + heuristic thresholds) ──────────────────────
# Kept in rules.json so they are tunable without a code edit, like everything else.
_L = CONFIG.get("limits", {})
MAX_URL_LEN             = int(_L.get("MAX_URL_LEN", 2048))          # input length cap
NEW_DOMAIN_MAX_AGE_DAYS = int(_L.get("NEW_DOMAIN_MAX_AGE_DAYS", 30))  # "new domain" bump age
RECENT_MAX_LIMIT        = int(_L.get("RECENT_MAX_LIMIT", 200))      # /recent page-size cap

# ── Model feature-block weights (part of the trained model's CONTRACT) ────────────
# The char-TF-IDF, word-TF-IDF and numeric feature blocks are combined with these
# fixed weights BOTH at train time (train_ml_strong.py) and at serve/probe time.
# They are baked into what model.pkl learned: changing them without a retrain
# silently shifts every score, and a train/serve mismatch is a silent accuracy
# bug. This is the single source of truth so the (many) call sites can't drift;
# locked by tests/test_feature_weights.py (value + train/serve golden score).
FEATURE_WEIGHTS = (0.05, 0.05, 15)   # (char_tfidf, word_tfidf, numeric)


def stack_features(x_char, x_word, x_num):
    """Combine the three feature blocks with FEATURE_WEIGHTS into one CSR matrix.

    The ONE place the block weighting is applied, so training and serving can
    never use different weights. Returns CSR (predict_proba-ready); the sparse
    storage format does not affect scores. scipy is imported lazily so tools that
    only need the rule lists don't pull it in.
    """
    from scipy.sparse import hstack
    wc, ww, wn = FEATURE_WEIGHTS
    return hstack([x_char * wc, x_word * ww, x_num * wn]).tocsr()


def strip_www(host: str) -> str:
    """Correctly remove a leading 'www.' prefix.

    NOTE: str.lstrip('www.') is a bug — it strips *characters* (w, ., ...),
    so 'www.whatsapp.com' would become 'hatsapp.com'. This does a true
    prefix strip.
    """
    host = host.lower()
    return host[4:] if host.startswith("www.") else host


# ── URL host parsing (shared by the serving layer) ───────────────────────────────
# One home for scheme detection + host extraction so predict_ml_only.py,
# main.py and features.py can't drift apart on how they read a URL.

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def ensure_scheme(url: str) -> str:
    """Prepend 'http://' when the input has no URL scheme.

    A bare host ('httpbin.org') or a scheme-less-but-http-prefixed host
    ('http-account.com', 'httpsecure.net') has NO '://', so urlparse/urlsplit
    would drop the host into the path and leave netloc empty. The old
    `url.startswith("http")` test treated those as already-schemed and
    misparsed them; a real scheme is '<scheme>://', so match exactly that.
    """
    url = str(url).strip()
    return url if _SCHEME_RE.match(url) else "http://" + url


def parse_host(url: str) -> str:
    """Extract the lowercase host from a URL, scheme-tolerant.

    Strips userinfo ('user:pass@'), the port, and a leading 'www.', and
    unwraps an [IPv6] literal ('[2001:db8::1]:443' → '2001:db8::1').
    Returns '' if nothing host-like is found.
    """
    try:
        netloc = urlsplit(ensure_scheme(url)).netloc
    except Exception:
        return ""
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[-1]
    if netloc.startswith("["):            # bracketed IPv6 literal
        host = netloc[1:].split("]", 1)[0]
    else:
        host = netloc.split(":", 1)[0]
    return strip_www(host.lower())


def host_is_ip(host: str) -> bool:
    """True iff host is a raw IPv4 or IPv6 literal (not a domain name)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def host_is_loopback(host: str) -> bool:
    """True for 'localhost' or any loopback IP literal (127.0.0.0/8, ::1).

    Matched on the PARSED HOST only — never a substring of the whole URL, so a
    URL like http://evil.tk/localhost can no longer force a SAFE verdict.
    """
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def csv_safe(value) -> str:
    """Neutralize CSV formula injection for spreadsheet consumers.

    Excel/Sheets evaluate a cell that begins with = + - @ (or a leading tab/CR
    they trim) as a formula when the file is opened, so a scanned URL such as
    '=HYPERLINK(...)' or '@SUM(...)' written verbatim to a CSV could execute in
    a reviewer's spreadsheet. Prefix any such value with a single quote so it is
    always treated as text. Both the false-positive log (main.py) and the Power
    BI export (export_to_bi.py) write user-controlled URLs, so both sanitize.
    """
    s = "" if value is None else str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s
