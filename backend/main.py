"""
PhishGuard AI — FastAPI Backend  v3.2.0  (serving model v3.5, decision threshold 0.6, keyword-gate 0.55)
  v3.0:   an exact known-phishing blocklist match is now a decisive PHISHING gate
          (Gate 2b), checked before the confident-safe fast path — see there.
  v3.0.1: that gate now also overrides the allowlist for shared-hosting commons
          (github.io, *.tumblr.com, ... = SHARED_HOSTING_ROOTS), while real-brand
          roots stay absolutely trusted — see Gate 2b.
  v3.0.2: a trusted-root allowlist hit that SURVIVES the blocklist now short-
          circuits to SAFE (Gate 2c), so the Gate-4 brand/subdomain heuristics
          can no longer drag a legit page on a trusted root (e.g.
          microsoft.github.io) to SUSPICIOUS — restoring the allowlist's core
          promise that a trusted root is never wrongly flagged.
  v3.1.0: host-parsing security hardening + serving robustness (no model change).
          The loopback, trusted-root, raw-IP and @-authority checks now key on
          the PARSED HOST, not on substrings of the whole URL. Closes the
          localhost bypass (http://evil.tk/localhost no longer forces SAFE) and
          the dotted-quad-in-path false raw-IP flag; scheme detection is a real
          '<scheme>://' test (config.parse_host / host_is_ip / host_is_loopback).
          Robustness: model inference + event logging run off the event loop
          (asyncio.to_thread); logging and the FP-log write can no longer 500 a
          verdict; CSV formula injection is neutralized (config.csv_safe); the
          /recent limit is clamped; the blocklist feed dir is anchored on the
          module path; check_phishtank was renamed to check_blocklist (honest —
          it reads a LOCAL OpenPhish/PhishTank union, not the live API).
  v3.2.0: model v3.5 retrain — no serving-logic change, model artifacts only.
          Two training-pipeline correctness fixes (see train_ml_strong.py /
          MODEL_AUDIT.md "v3.5"): (M10) the TF-IDF vectorizers and the scaler are
          now fit on the TRAIN slice only — previously they were fit on the full
          set before the grouped split, so the held-out score was mildly leaky;
          (M11) XGBoost pins random_state + n_jobs=1, so training is bit-
          reproducible and the golden model-only scores in tests are a real lock.
          The feature-block weight triple is now the single shared helper
          config.stack_features (H3), so train and serve can never drift. Gated:
          model-only FP fell 6.91% -> 6.23% on the 80k sweep (< the 9.70% ceiling),
          equal-FP recall 61.2% -> 61.3%, homograph 14/14, byjus deep-paths SAFE.
Endpoints: /predict_url  /stats  /recent  /health  /report_false_positive

Rule lists, scoring weights, thresholds, network timeouts and serving limits
(max URL length, new-domain age, /recent cap) all load from rules.json via
config.py. A handful of operational knobs stay as environment variables
(CORS_ORIGINS, FP_LOG_PATH, RAW_FEED_DIR, PHISHGUARD_DB) so deployment can set
them without editing rules; those are documented at their use sites below.
"""

import asyncio
import csv
import datetime
import os
import re
import ssl
import socket
import time
import whois

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from predict_ml_only import predict_ml
from database import log_event, get_stats, get_recent_events
from config import (
    strip_www, BRANDS, KEYWORDS, SHARED_HOSTING_ROOTS,
    parse_host, host_is_ip, csv_safe,
    ML_SAFE_THRESHOLD, ML_DECISION_THRESHOLD, W_BRAND, W_TYPO, W_SUBDOMAIN, W_IP,
    W_NEW_DOMAIN, W_NO_SSL, W_KEYWORD, KEYWORD_MIN_PROB, DAMPENER_THRESHOLD,
    T_PHISHING, T_SUSPICIOUS,
    WHOIS_TIMEOUT_SEC, SSL_TIMEOUT_SEC, META_CACHE_TTL_SEC,
    MAX_URL_LEN, NEW_DOMAIN_MAX_AGE_DAYS, RECENT_MAX_LIMIT,
)

app = FastAPI(title="PhishGuard AI", version="3.2.0")
# CORS: defaults to "*" for the local demo. Set CORS_ORIGINS (comma-separated)
# to lock it down in production without a code change, e.g.
#   CORS_ORIGINS="https://phishguard.example.com,http://localhost:3000"
_cors_origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "*").split(",") if o.strip()] or ["*"]
app.add_middleware(CORSMiddleware, allow_origins=_cors_origins,
                   allow_methods=["*"], allow_headers=["*"])


# ── Request models ────────────────────────────────────────────────────────────

class URLRequest(BaseModel):
    url: str

class FalsePositiveReport(BaseModel):
    url: str
    reason: str = ""


FP_LOG = os.environ.get("FP_LOG_PATH", "pending_retrain.csv")

# Keywords used by the heuristic keyword-flag (subset of config KEYWORDS is fine;
# we use the full list so it stays in sync with rules.json).
_KEYWORD_FLAG_SET = set(KEYWORDS)


# ── Input hardening / de-fanging (D5) ────────────────────────────────────────────
# URL length cap (MAX_URL_LEN) comes from rules.json → config, tunable without a
# code change; guards against pathological input.

def _normalize_url(raw: str) -> str:
    """Sanitize and de-fang user input before analysis.

    - trims whitespace and caps length (avoids pathological/abusive input)
    - converts common 'defanged' threat-intel notations back to a live URL, so
      a pasted `hxxp://evil[.]com` is analyzed as `http://evil.com` rather than
      mis-parsed. features.py also strips brackets, but normalizing here means
      WHOIS / SSL / domain extraction all operate on the same clean URL.
    """
    u = str(raw or "").strip()
    if len(u) > MAX_URL_LEN:
        u = u[:MAX_URL_LEN]
    u = re.sub(r"(?i)^hxxp", "http", u)                  # hxxp:// / hxxps:// -> http(s)://
    u = re.sub(r"(?i)\[\s*dot\s*\]", ".", u)             # evil[dot]com -> evil.com
    u = (u.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
           .replace("[:]", ":").replace("[/]", "/"))
    # Strip stray de-fang brackets, but PRESERVE an [IPv6] literal host so a raw
    # IPv6 address stays parseable as the host ( http://[2001:db8::1]/ ). The
    # specific de-fang forms above are already gone by here; a bracketed hex:colon
    # run is an IPv6 literal, not a de-fanged dot (de-fanged IPv6 is never pasted).
    if not re.search(r"\[[0-9a-fA-F:]+\]", u):
        u = u.replace("[", "").replace("]", "")              # any stray brackets
    # Collapse runs of redundant slashes OUTSIDE the scheme separator, so that
    #   byjus.com//////login  ->  byjus.com/login
    # A legit root padded with many slashes was inflating URL features and
    # creeping the model over the line; a real browser collapses these too. The
    # negative-lookbehind on ':' preserves the scheme's own '://'.
    u = re.sub(r"(?<!:)/{2,}", "/", u)
    return u.strip()


# ── Network helpers (blocking; called via threads with timeout + TTL cache) ─────

def get_domain_age(domain: str) -> int:
    try:
        w  = whois.whois(domain)
        cd = w.creation_date
        if not cd: return -1
        if isinstance(cd, list): cd = cd[0]
        if isinstance(cd, str):  return -1
        return (datetime.datetime.now() - cd).days
    except Exception:
        return -1

def check_ssl(domain: str) -> bool:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=SSL_TIMEOUT_SEC) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                return bool(ssock.getpeercert())
    except Exception:
        return False

# ── D1: local phishing blocklist snapshot (replaces the dead live feed) ─────────
# The old check_phishtank POSTed to checkurl.phishtank.com, which is now
# key-gated/deprecated over http and effectively always returned False, so the
# W_PHISHTANK signal never fired. Instead we load a LOCAL snapshot of the same
# feeds we already ship for training (data/raw/openphish.txt + phishtank.csv)
# into an in-memory set once at startup and do an exact normalized-URL lookup.
# (The lookup function is check_blocklist() — renamed from the misleading
# check_phishtank(), since it consults a local OpenPhish/PhishTank union, not
# the live PhishTank API.)
#
# Exact-URL match (not root match) is deliberate: these feeds are dominated by
# shared free-hosting roots (weebly/webflow/vercel/...), which the A5 training
# filter treats as noise — blocking a whole such root would nuke legit sites, so
# we only flag the specific URL that was reported.
#
# Staleness: this snapshot is from the shipped feeds (~April 2025). It is a
# best-effort corroborating signal, NOT the primary verdict. Refresh path: drop
# fresh openphish.txt / phishtank.csv into data/raw/ and restart (or wire a cron
# that re-downloads them); an authenticated live API could later replace this.
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
_RAW_DIR = os.environ.get("RAW_FEED_DIR", os.path.join(_BACKEND_DIR, "..", "data", "raw"))

def _load_local_blocklist() -> frozenset:
    urls: set[str] = set()
    def _add(raw: str):
        n = _normalize_url(raw)
        if not n or "." not in n:
            return
        urls.add(n)
        urls.add(n.rstrip("/"))          # tolerate trailing-slash variance
    # OpenPhish: one URL per line
    op = os.path.join(_RAW_DIR, "openphish.txt")
    try:
        with open(op, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    _add(line)
    except FileNotFoundError:
        pass
    # PhishTank: CSV with a 'url' column
    pt = os.path.join(_RAW_DIR, "phishtank.csv")
    try:
        with open(pt, encoding="utf-8", errors="ignore", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                u = (row.get("url") or "").strip()
                if u:
                    _add(u)
    except FileNotFoundError:
        pass
    return frozenset(urls)

_PHISH_BLOCKLIST = _load_local_blocklist()
print(f"[PhishGuard] local blocklist loaded: {len(_PHISH_BLOCKLIST):,} URL entries")

def check_blocklist(url: str) -> bool:
    """Exact-match lookup against the local blocklist snapshot (offline, instant).
    `url` is already normalized by the endpoint, so a plain membership test —
    plus the trailing-slash-stripped form — is enough.

    (Formerly check_phishtank; renamed because it consults a LOCAL
    OpenPhish/PhishTank union snapshot, not the live PhishTank API.)"""
    return url in _PHISH_BLOCKLIST or url.rstrip("/") in _PHISH_BLOCKLIST


# ── Async wrappers: bound every network call by a timeout + cache per domain ────
# whois in particular has no built-in timeout and can hang for many seconds;
# wait_for guarantees the request stays responsive, and the cache avoids
# re-querying the same domain within META_CACHE_TTL_SEC.

_age_cache: dict[str, tuple[float, int]] = {}
_ssl_cache: dict[str, tuple[float, bool]] = {}

def _cache_get(cache: dict, key: str):
    entry = cache.get(key)
    if entry and (time.time() - entry[0]) < META_CACHE_TTL_SEC:
        return True, entry[1]
    return False, None

async def _age_async(domain: str) -> int:
    hit, val = _cache_get(_age_cache, domain)
    if hit:
        return val
    try:
        val = await asyncio.wait_for(
            asyncio.to_thread(get_domain_age, domain), timeout=WHOIS_TIMEOUT_SEC)
    except Exception:
        val = -1
    _age_cache[domain] = (time.time(), val)
    return val

async def _ssl_async(domain: str) -> bool:
    hit, val = _cache_get(_ssl_cache, domain)
    if hit:
        return val
    try:
        val = await asyncio.wait_for(
            asyncio.to_thread(check_ssl, domain), timeout=SSL_TIMEOUT_SEC + 1)
    except Exception:
        val = False
    _ssl_cache[domain] = (time.time(), val)
    return val

# (The blocklist is consulted synchronously via check_blocklist() at the
#  decisive Gate 2b in /predict_url — instant frozenset lookup, no async
#  wrapper needed, unlike the network-bound whois/SSL helpers above.)


# ── Domain / brand helpers ──────────────────────────────────────────────────────

def extract_domain(url: str) -> str:
    # Scheme-tolerant, userinfo/port-stripped, IPv6-bracket-aware host (config
    # helper). Replaces the old `startswith("http")` parse that mis-read
    # scheme-less http-prefixed hosts and split IPv6 literals on their colons.
    return parse_host(url)

def levenshtein(a: str, b: str) -> int:
    dp = [[0] * (len(b)+1) for _ in range(len(a)+1)]
    for i in range(len(a)+1):
        for j in range(len(b)+1):
            if i == 0: dp[i][j] = j
            elif j == 0: dp[i][j] = i
            elif a[i-1] == b[j-1]: dp[i][j] = dp[i-1][j-1]
            else: dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
    return dp[-1][-1]

def check_typo(domain: str):
    name = domain.split(".")[0]
    for b in BRANDS:
        if levenshtein(name, b) == 1:
            return True, b
    return False, None

def check_subdomain(url: str):
    host  = url.split("//")[-1].split("/")[0]
    parts = host.split(".")
    if len(parts) > 2:
        for p in parts[:-2]:
            if p in BRANDS: return True, p
    return False, None

def is_legit_brand_domain(domain: str, brand: str) -> bool:
    d = domain.lower()
    return d == brand or d == brand+".com" or d.endswith("."+brand+".com")

def is_shared_hosting_host(domain: str) -> bool:
    """True when `domain` is (a host under) a shared-hosting commons root —
    e.g. foo.github.io, user.tumblr.com. These trusted roots host third-party
    content, so their trust belongs to the platform, not the tenant. Used at
    Gate 2b to let an EXACT blocklist match override the allowlist for such a
    URL while real-brand roots (google.com) stay absolutely trusted."""
    d = strip_www(domain)
    return any(d == r or d.endswith("." + r) for r in SHARED_HOSTING_ROOTS)

def _build_url_response(url, domain, prob, score, result, reasons, age, ssl_valid):
    return {
        "type":           "url",
        "input":          str(url),
        "domain":         str(domain),
        "ml_probability": float(round(float(prob),  4)),
        "risk_score":     float(round(float(score), 2)),
        "result":         str(result),
        "reasons":        list(reasons),
        "meta": {
            "domain_age_days": int(age),
            "ssl_valid":       (None if ssl_valid is None else bool(ssl_valid)),
        },
    }


async def _log_event_safe(*args) -> None:
    """Persist a detection event WITHOUT letting the DB block or break the request.

    log_event opens a SQLite connection and writes — a blocking I/O call — so we
    run it in a worker thread to keep the async event loop responsive under load.
    Logging is a side effect: a DB hiccup (locked file, disk full) must never turn
    a good verdict into a 500, so any error is swallowed after a stderr note.
    """
    try:
        await asyncio.to_thread(log_event, *args)
    except Exception as e:                       # pragma: no cover - defensive
        print(f"[PhishGuard] log_event failed (non-fatal): {e!r}")


# ── /predict_url ──────────────────────────────────────────────────────────────

@app.post("/predict_url")
async def predict_url_endpoint(req: URLRequest):
    url = _normalize_url(req.url)
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    start  = datetime.datetime.utcnow()
    domain = extract_domain(url)

    # ── Gate 1: ML model ─────────────────────────────────────────────────────
    # predict_ml is CPU-bound (TF-IDF transform + XGBoost predict); run it in a
    # worker thread so a burst of requests can't serialize on the event loop.
    pred, prob, override_reason = await asyncio.to_thread(predict_ml, url)

    # ── Gate 2: Absolute threat (@ trick / raw IP / brand spoofing) ───────────
    if override_reason and "Critical" in override_reason:
        ssl_valid, age = await asyncio.gather(_ssl_async(domain), _age_async(domain))
        result, score = "PHISHING", 10.0
        reasons = [override_reason]
        elapsed = (datetime.datetime.utcnow() - start).total_seconds()
        await _log_event_safe("url", url, result, score, elapsed)
        return _build_url_response(url, domain, prob, score, result, reasons, age, ssl_valid)

    # ── Gate 2b: Known-phishing blocklist → decisive PHISHING ─────────────────
    # An exact match against the local known-phishing blocklist (live
    # OpenPhish/PhishTank, refreshable via refresh_feeds.py) is the strongest
    # reputation signal available, so it forces PHISHING outright — the same
    # standing as a structural override. Checked HERE, before the Gate-3
    # confident-safe fast path, on purpose: the compromised-/benign-host case
    # (a real-looking host the model scores ~0, e.g. a weaponized github.io
    # clone page) is exactly where the blocklist must win — and the old Gate-4
    # score bump both (a) was never reached for those URLs (Gate 3 returned
    # SAFE first) and (b) got halved by the confidence dampener when it was.
    #
    # Allowlist interaction (v3.0.1): the blocklist normally yields to the
    # allowlist (override_reason is None ⇒ the model actually scored the URL).
    # The ONE carve-out is a shared-hosting commons — github.io, *.tumblr.com,
    # etc. (SHARED_HOSTING_ROOTS): those roots are on the allowlist only as an
    # FP guard (the model over-flags legit pages there 0.6–0.99), but their
    # trust belongs to the PLATFORM, not the tenant, so an exact blocklist match
    # on such a URL SHOULD win. A legit page on those roots is never on the
    # blocklist, so it stays SAFE; only the specific reported URL flips. Real
    # brand roots (google.com, paypal.com) are NOT shared-hosting, so a stale
    # feed entry can never flip a brand — see AskUserQuestion "shared hosts only".
    _shared_host_allowlisted = (
        override_reason == "Globally trusted domain"
        and is_shared_hosting_host(domain)
    )
    if check_blocklist(url) and (override_reason is None or _shared_host_allowlisted):
        ssl_valid, age = await asyncio.gather(_ssl_async(domain), _age_async(domain))
        reason = "URL in known-phishing blocklist (OpenPhish/PhishTank)"
        if _shared_host_allowlisted:
            reason += " — phishing page on a shared-hosting platform (overrides root trust)"
        result, score, reasons = "PHISHING", 9.0, [reason]
        elapsed = (datetime.datetime.utcnow() - start).total_seconds()
        await _log_event_safe("url", url, result, score, elapsed)
        return _build_url_response(url, domain, prob, score, result, reasons, age, ssl_valid)

    # ── Gate 2c: trusted-root allowlist → honor SAFE ──────────────────────────
    # predict_ml flagged this URL's registrable root as globally trusted (the
    # allowlist FP guard). The blocklist just had its chance to override at
    # Gate 2b; since it didn't fire, the allowlist verdict STANDS as SAFE and we
    # return HERE — rather than falling into Gate 4, whose brand/subdomain
    # heuristics assume an UNtrusted root and would otherwise drag a legit page
    # on a trusted root up to SUSPICIOUS. Concrete FP this fixes:
    #   microsoft.github.io/monaco-editor/  — the label 'microsoft' reads as a
    #   brand-in-subdomain trick (+W_BRAND +W_SUBDOMAIN ≈ 6.0, dampened to
    #   ~3.0, a hair over T_SUSPICIOUS=3.0), yet github.io is allowlisted and the
    #   page is a real Microsoft project. Every <brand>.github.io project page
    #   (google.github.io, kubernetes.github.io, ...) hit the same trap.
    # The allowlist's whole contract is "a trusted root is never wrongly
    # flagged"; Gate 2b (blocklisted shared-host phishing) is the sole, deliberate
    # exception, and it runs first — so honoring SAFE here is safe. Localhost and
    # any other non-allowlist override keep flowing to Gate 3 (its own SAFE path).
    if override_reason == "Globally trusted domain":
        score   = round(prob * 3, 2)
        reasons = [override_reason, "ML: low phishing probability"]
        elapsed = (datetime.datetime.utcnow() - start).total_seconds()
        await _log_event_safe("url", url, "SAFE", score, elapsed)
        return _build_url_response(url, domain, prob, score, "SAFE", reasons, -1, None)

    # ── Gate 3: ML confident site is safe → deterministic fast path ──────────
    # D2: the SAFE verdict is NO LONGER gated on live SSL. SSL validity is
    # near-noise (modern phishing overwhelmingly has valid Let's Encrypt certs;
    # legit sites fail the check on flaky networks) and gating on it made the
    # verdict non-deterministic across runs. Instead we fast-path to SAFE only
    # when the model is confident AND no cheap, deterministic LOCAL structural
    # flag fires (typo-squat / brand-in-subdomain / brand-in-domain) — those
    # still deserve the full Gate-4 heuristic. SSL is skipped entirely here, so
    # confident-safe sites return in milliseconds and ssl_valid is reported as
    # null ("not checked"), mirroring how domain age is already reported.
    if pred == 0 and prob < ML_SAFE_THRESHOLD:
        typo_flag, _ = check_typo(domain)
        sub_flag,  _ = check_subdomain(url)
        brand_flag   = any(b in domain and not is_legit_brand_domain(domain, b) for b in BRANDS)
        if not (typo_flag or sub_flag or brand_flag):
            score   = round(prob * 3, 2)
            result  = "SAFE"
            reasons = ["ML: low phishing probability"]
            if override_reason: reasons.insert(0, override_reason)
            elapsed = (datetime.datetime.utcnow() - start).total_seconds()
            await _log_event_safe("url", url, result, score, elapsed)
            return _build_url_response(url, domain, prob, score, result, reasons, -1, None)

    # ── Gate 4: Full heuristic pipeline (ML is uncertain) ────────────────────
    age, ssl_valid = await asyncio.gather(
        _age_async(domain),
        _ssl_async(domain),
    )

    brand_flag = any(b in domain and not is_legit_brand_domain(domain, b) for b in BRANDS)
    # Keyword bump only CORROBORATES when the model already leans phishing.
    # KEYWORD_MIN_PROB was raised 0.40 -> 0.55 (v2.9) on evidence from
    # keyword_rule_probe.py: at 0.40 the +1.5 bump pushed real sites' ordinary
    # /login, /account, /secure/checkout pages (model prob ~0.52) over the
    # SUSPICIOUS line — a soft false alarm on legit hosts. 0.55 sits between the
    # safe fast-path (0.35) and the decision line (0.6): it cut real-site false
    # alarms ~15% (Tranco 6.85%->5.80%) for a measured recall cost of only
    # 13-in-8000 phishing (compromised-host/redirect URLs the local blocklist
    # also covers). See MODEL_AUDIT.md "keyword-rule operating point".
    keyword_flag = (
        prob >= KEYWORD_MIN_PROB
        and any(k in url.lower() for k in _KEYWORD_FLAG_SET)
    )
    # Raw-IP tell keys on the actual HOST being an IP literal (v4/v6), not on a
    # dotted quad anywhere in the URL — so a '/v1.2.3.4/' style version path in
    # a legit URL no longer adds the W_IP penalty.
    ip_flag        = host_is_ip(domain)
    typo_flag, typo_brand = check_typo(domain)
    sub_flag,  sub_brand  = check_subdomain(url)

    score   = prob * 3
    reasons = []

    if override_reason: reasons.append(override_reason)

    if prob > 0.7:  reasons.append("ML: high phishing probability")
    elif prob > 0.4: reasons.append("ML: moderate risk detected")

    if brand_flag:  score += W_BRAND;    reasons.append("Brand impersonation in domain")
    if typo_flag:   score += W_TYPO;     reasons.append(f"Typo-squatting on '{typo_brand}'")
    if sub_flag:    score += W_SUBDOMAIN; reasons.append(f"Subdomain trick on '{sub_brand}'")
    if ip_flag:     score += W_IP;       reasons.append("Raw IP address used as host")
    if keyword_flag: score += W_KEYWORD; reasons.append("Suspicious keywords in URL (ML-confirmed)")
    if age != -1 and age < NEW_DOMAIN_MAX_AGE_DAYS: score += W_NEW_DOMAIN; reasons.append(f"Domain only {age} days old")
    if not ssl_valid: score += W_NO_SSL; reasons.append("No valid SSL certificate")

    if prob < DAMPENER_THRESHOLD:
        score = score * 0.5
        reasons.append("Heuristics dampened: ML confident site is safe")

    if score > T_PHISHING:    result = "PHISHING"
    elif score >= T_SUSPICIOUS: result = "SUSPICIOUS"
    else:                       result = "SAFE"

    score   = round(score, 2)
    elapsed = (datetime.datetime.utcnow() - start).total_seconds()
    await _log_event_safe("url", url, result, score, elapsed)
    return _build_url_response(url, domain, prob, score, result, reasons, age, ssl_valid)


# ── /report_false_positive ────────────────────────────────────────────────────

@app.post("/report_false_positive")
async def report_false_positive(rep: FalsePositiveReport):
    url    = _normalize_url(rep.url)
    domain = extract_domain(url)
    # csv_safe: this row is user-controlled (url/reason) and gets opened in Excel/
    # Sheets during retrain triage — neutralize CSV formula injection (=,+,-,@).
    row    = {"url": csv_safe(url), "type": "legitimate", "domain": csv_safe(domain),
              "reason": csv_safe(rep.reason),
              "reported": datetime.datetime.utcnow().isoformat()}

    try:
        file_exists = os.path.isfile(FP_LOG)
        with open(FP_LOG, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=row.keys())
            if not file_exists: writer.writeheader()
            writer.writerow(row)
    except OSError as e:
        # A full disk or read-only FS must not turn a user's FP report into a 500.
        print(f"[PhishGuard] FP-log write failed (non-fatal): {e!r}")
        return {"status": "accepted", "url": url, "domain": domain,
                "note": "report received but could not be persisted"}

    return {"status": "logged", "url": url, "domain": domain}


# ── Standard endpoints ────────────────────────────────────────────────────────
@app.get("/")
def read_root():
    return {"message": "PhishGuard AI Backend is running!", "status": "Active"}

@app.get("/stats")
def stats():  return get_stats()

@app.get("/recent")
def recent(limit: int = 20):
    # Clamp to a sane window: a negative LIMIT is SQLite's "all rows" (would dump
    # the whole table), and an unbounded large value is a cheap DoS. RECENT_MAX_LIMIT
    # comes from rules.json. database.get_recent_events clamps defensively too.
    limit = max(1, min(limit, RECENT_MAX_LIMIT))
    return get_recent_events(limit)

@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": app.version,
        "model": "v3.5",
        "decision_threshold": ML_DECISION_THRESHOLD,
        "keyword_min_prob": KEYWORD_MIN_PROB,
    }
