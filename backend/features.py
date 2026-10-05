import re
import math
import unicodedata
from urllib.parse import urlparse
from rapidfuzz import fuzz

# Rule lists come from rules.json (see config.py) — no hardcoded lists here.
from config import BRANDS as brands, KEYWORDS as keywords, SUSPICIOUS_TLDS, ensure_scheme

# Common homoglyphs used in IDN/homograph attacks (Cyrillic/Greek/look-alikes
# that render like ASCII letters). Mapped to their ASCII twin so a de-confused
# "skeleton" of the host can be compared against the real brand names. NFKD in
# _skeleton() also folds full-width / accented forms, so this only needs the
# same-looking-but-different-codepoint cases.
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ո": "n", "м": "m",
    "т": "t", "в": "b", "к": "k", "г": "r", "н": "h", "и": "u",
    "ο": "o", "α": "a", "ρ": "p", "ε": "e", "τ": "t", "ι": "i", "κ": "k",
    "ν": "v", "μ": "u", "χ": "x", "γ": "y", "π": "n", "θ": "o",
    "ⅼ": "l", "ӏ": "l", "１": "1", "０": "0",
}


def entropy(url):
    if not url: return 0
    prob = [url.count(c)/len(url) for c in set(url)]
    return -sum(p * math.log(p, 2) for p in prob)

def clean_text(s):
    return re.sub(r'[^a-z0-9]', '', s)


def _decode_idn(host):
    """Decode any xn-- (punycode) labels in a host back to Unicode, so a
    homograph domain registered as `xn--pple-43d.com` is compared as the
    look-alike Unicode it renders to. Best-effort: a label that fails to
    decode is left as-is. Pure-ASCII hosts pass through unchanged."""
    out = []
    for label in host.split('.'):
        if label.startswith('xn--'):
            try:
                out.append(label[4:].encode('ascii').decode('punycode'))
            except Exception:
                out.append(label)
        else:
            out.append(label)
    return '.'.join(out)


def _skeleton(s):
    """Reduce a (possibly Unicode) string to a de-confused ASCII 'skeleton':
    NFKD-fold accents / full-width / compatibility forms, then map known
    homoglyphs (Cyrillic/Greek/look-alikes) to their ASCII twin. A pure-ASCII
    string is returned unchanged, so legit hosts are NOT altered — this only
    strengthens the brand fuzzy match against IDN/homograph spoofs."""
    s = unicodedata.normalize('NFKD', s)
    out = []
    for c in s:
        if c in _CONFUSABLES:
            out.append(_CONFUSABLES[c])
        elif ord(c) < 128:
            out.append(c)
        # else: unmappable non-ASCII (combining marks, other scripts) — drop
    return ''.join(out)


def extract_features(url):
    try:
        url = str(url).lower().strip()

        # Strip rogue brackets that crash Python's URL parser
        url = url.replace('[', '').replace(']', '')

        # Prepend a scheme only when there is NO real '<scheme>://'. The old
        # `not url.startswith("http")` test misfired on scheme-less hosts that
        # merely start with 'http' (e.g. 'http-login.tk', 'httpbin.org'):
        # urlparse then left netloc empty and every host feature read as 0.
        url = ensure_scheme(url)

        parsed = urlparse(url)
        # authority = the netloc exactly as parsed, BEFORE we strip userinfo.
        # The credential-hiding "@" trick lives here (http://legit.com@evil.com);
        # an "@" in the path or query (e.g. ?email=a@b.com) is harmless and must
        # NOT be treated as the trick. So all "@" checks below use `authority`.
        authority = parsed.netloc
        host = parsed.netloc

        if "@" in host: host = host.split("@")[-1]
        if ":" in host: host = host.split(":")[0]
        if host.startswith("www."): host = host[4:]

        parts = host.split(".")
        domain = parts[-2] if len(parts) > 1 else parts[0]
        suffix = parts[-1] if len(parts) > 1 else ""
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

        features = []

        # -------- BASIC --------
        features.append(len(url)/100) # 0
        features.append(url.count('.')) # 1
        features.append(url.count('-')) # 2
        features.append(url.count('/')) # 3
        features.append(sum(c.isdigit() for c in url)) # 4
        features.append(entropy(url)) # 5

        # -------- KEYWORDS --------
        kw_count = sum(k in url for k in keywords)
        features.append(kw_count) # 6

        # -------- DEEP BRAND ANALYSIS (host-only, path-safe) --------
        # IDN-decode then de-confuse the host so homograph spoofs
        # (xn--pple-43d.com, or raw-Unicode "аpple.com") match real brands.
        # For pure-ASCII hosts host_skel == host, so nothing changes there.
        host_idn = _decode_idn(host)
        host_skel = _skeleton(host_idn)
        host_pieces = set(re.split(r'[.\-]', host)) | set(re.split(r'[.\-]', host_skel))

        max_sim = 0
        brand_spoof_flag = 0

        for b in brands:
            for piece in host_pieces:
                clean_p = clean_text(piece)
                norm_p = clean_p.replace('0', 'o').replace('1', 'l').replace('3', 'e')

                if len(norm_p) >= 4:
                    score = fuzz.ratio(norm_p, b)
                    if score > 85:
                        max_sim = max(max_sim, score)
                        if domain != b:
                            brand_spoof_flag = 1

        features.append(max_sim / 100) # 7
        features.append(brand_spoof_flag) # 8
        features.append(int(brand_spoof_flag == 1 and kw_count > 0)) # 9

        # -------- STRUCTURE --------
        features.append(1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0) # 10 (IP Address)
        features.append(int("@" in authority)) # 11 (@ credential trick — authority only)
        features.append(int("@" in authority and "." in authority.split("@")[-1])) # 12
        features.append(len([x for x in parsed.path.split("/") if x])) # 13
        features.append(int("-" in domain)) # 14
        features.append(len(subdomain.split(".")) if subdomain else 0) # 15
        features.append(int(suffix in SUSPICIOUS_TLDS)) # 16
        features.append(int("localhost" in url or "127.0.0.1" in url)) # 17

        # -------- HOST-LEVEL PHISHING SIGNALS (added v2.4) --------
        # Catches keyword-salad hostnames like "verify-your-bank-account-now.net"
        # where the model previously under-scored (no brand, benign-looking TLD).
        host_tokens = [t for t in re.split(r'[.\-]', host) if t]
        host_kw_tokens = sum(1 for t in host_tokens if t in keywords)
        features.append(host_kw_tokens)          # 18 (exact keyword tokens in host)
        features.append(host.count('-'))         # 19 (hyphens in host only)

        # -------- IDN / HOMOGRAPH SIGNALS (added v3.1) --------
        # Structural, not brand-specific: most legit hosts are pure ASCII, so
        # both are 0 for them. They flag the rare IDN/punycode host, which —
        # combined with the skeleton brand match above (feat 8) — is how a
        # homograph spoof like xn--pple-43d.com now surfaces.
        features.append(int("xn--" in host))                        # 20 (punycode label present)
        features.append(int(any(ord(c) > 127 for c in host_idn)))   # 21 (non-ASCII host after IDN decode)

        return features

    except Exception:
        # BULLETPROOF fallback — length must match the feature count above (22)
        return [0] * 22
