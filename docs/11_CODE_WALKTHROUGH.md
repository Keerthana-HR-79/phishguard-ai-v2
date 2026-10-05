# 11 — Code Walkthrough (annotated, real code)

> Docs 09 and 10 tell you *what* each file is and *that* its functions exist. **This doc opens the
> files and walks the actual code**, line-group by line-group, so you can read along and defend any
> part of it. Every snippet below is copied from the live source, trimmed only where noted with `…`.
>
> Read the two maps first (they answer *"how is it all connected?"*), then the per-file walkthroughs,
> then the end-to-end trace at the bottom.

---

## MAP 1 — the runtime import graph (what wires to what, at serve time)

```
                         rules.json   (all lists, weights, thresholds — pure data)
                             │  loaded once
                             ▼
                          config.py  ────────────────────────────────┐
             (constants + parse_host/host_is_ip/stack_features/csv_safe)
                             │                      │                 │
          ┌──────────────────┤                      │                 │
          ▼                  ▼                      ▼                 ▼
     features.py       predict_ml_only.py        main.py          database.py
   (URL → 22 nums)   (loads model.pkl +         (FastAPI app,     (SQLite log +
          ▲            3 vectorizers;            the 6 gates)       stats)
          │            Gate 0/1 + ML score)        │  │  │
          │                  ▲                      │  │  └─► database.log_event / get_stats / get_recent
          └──────────────────┘                      │  └────► predict_ml_only.predict_ml   (Gate 1)
                 (predict_ml calls                   └───────► features/config helpers    (Gates 2–4)
                  extract_features)
                             ▲
                             │  HTTP POST /predict_url
            ┌────────────────┴───────────────────┐
            ▼                                     ▼
   frontend/ (url-checker.html,            extension/ (background.js
   dashboard.html + js/)                   service worker + popup.js)
```

**One sentence:** `rules.json` → `config.py` is the base everything imports; `features.py` turns a URL
into numbers; `predict_ml_only.py` owns the model and the first two safety checks; `main.py` is the web
server that calls the model first and then applies the rule gates; `database.py` records every verdict;
the frontend and the Chrome extension are two clients that both POST to the same `/predict_url`.

The key design fact to say out loud: **the arrows point `config.py` → everything.** All the magic
numbers live in one JSON file loaded in one module, so there are no hardcoded lists scattered around.

---

## MAP 2 — the training data flow (how model.pkl is made, offline)

```
 data/processed/*.csv ─┐
 (final_dataset,       │  pd.read_csv
  legit_urls,          ▼
  adversarial,     train_ml_strong.py
  fresh_phishing)       │
                        │ 1. drop label-noise roots (trusted + shorteners)
                        │ 2. balance 50/50, cap 150k per class
                        │ 3. AUGMENT: emit each URL bare + pathed  ─────► url_augment.add_path
                        │ 4. GROUP-SPLIT by registrable domain     ─────► url_augment.registrable_domain
                        │ 5. fit char/word TF-IDF + scaler ON TRAIN ONLY
                        │ 6. stack blocks with weights             ─────► config.stack_features
                        │ 7. XGBoost.fit  (seed, n_jobs=1)
                        │ 8. isotonic calibrate on DISJOINT slice
                        │ 9. pickle.dump
                        ▼
         model.pkl  char_vectorizer.pkl  word_vectorizer.pkl  scaler.pkl
                        │
                        │  (same 4 files loaded by…)
                        ▼
         predict_ml_only.py (serving)   AND   fp_sweep.py (the gate probe)
```

The thing that makes training and serving agree: **both sides build the feature matrix the same way**
— `extract_features()` for the 22 numbers, the same pickled vectorizers, and the same
`config.stack_features()` weighting helper. If those drifted, the model would score differently in
training vs production (a silent accuracy bug). That's why the weighting lives in *one* function.

---

# PART A — The runtime files

## A1. `rules.json` → `config.py` — the single source of truth

Nothing in the system hardcodes a brand name, a weight, or a threshold. They all live in `rules.json`,
and `config.py` loads that file **once** at import and exposes typed constants.

```python
_CFG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")
with open(_CFG_PATH, "r", encoding="utf-8") as _f:
    CONFIG = json.load(_f)

BRANDS          = [b.lower() for b in CONFIG["brands"]]
KEYWORDS        = [k.lower() for k in CONFIG["keywords"]]
SUSPICIOUS_TLDS = [t.lower().lstrip(".") for t in CONFIG["suspicious_tlds"]]
TRUSTED_ROOTS   = {d.lower() for d in CONFIG["trusted_roots"]}
```

- `os.path.dirname(os.path.abspath(__file__))` anchors the path on **this file's folder**, not the
  process working directory — so `uvicorn` started from any folder still finds `rules.json`. (Same
  `__file__`-anchoring trick is used for `model.pkl` and the blocklist feed.)
- `TRUSTED_ROOTS` is a **set** (`{…}`) not a list — membership tests (`root in TRUSTED_ROOTS`) are O(1).

**A safety invariant enforced at import time** — this is a great "I think about correctness" talking
point:

```python
SHARED_HOSTING_ROOTS = {d.lower() for d in CONFIG.get("shared_hosting_roots", [])}
_orphan_shared = SHARED_HOSTING_ROOTS - TRUSTED_ROOTS
assert not _orphan_shared, (
    f"shared_hosting_roots must be a subset of trusted_roots; "
    f"not in trusted_roots: {sorted(_orphan_shared)}"
)
```
`SHARED_HOSTING_ROOTS` (github.io, blogspot.com…) *must* be a subset of `TRUSTED_ROOTS` or the Gate-2b
override logic can never fire. Rather than trust a future `rules.json` edit to keep that true, the
module **asserts it on load** — a bad edit crashes the server at startup instead of silently breaking a
security gate. *If asked "how do you stop config drift?" → this line.*

### The host-parsing helpers (a security fix lives here)

```python
def parse_host(url: str) -> str:
    """Extract the lowercase host from a URL, scheme-tolerant."""
    try:
        netloc = urlsplit(ensure_scheme(url)).netloc
    except Exception:
        return ""
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[-1]      # drop user:pass@ (credential trick)
    if netloc.startswith("["):                  # bracketed IPv6 literal
        host = netloc[1:].split("]", 1)[0]
    else:
        host = netloc.split(":", 1)[0]          # drop :port
    return strip_www(host.lower())
```

```python
def host_is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback   # 127.0.0.0/8, ::1
    except ValueError:
        return False
```

**Why this matters (defensible security point):** the earlier version checked
`"localhost" in url` — a *substring of the whole URL*. That meant `http://evil.tk/localhost` contained
the word "localhost" and got force-marked SAFE. Now the check runs on the **parsed host only**
(`parse_host` → `host_is_loopback`), so a keyword in the *path* can't spoof it. Same idea fixed a
false raw-IP flag from a `/v1.2.3.4/` version path.

And the little bug-with-a-story everyone loves:

```python
def strip_www(host: str) -> str:
    # NOTE: str.lstrip('www.') is a bug — it strips *characters* (w, ., ...),
    # so 'www.whatsapp.com' would become 'hatsapp.com'. This does a true prefix strip.
    host = host.lower()
    return host[4:] if host.startswith("www.") else host
```
`"www.whatsapp.com".lstrip("www.")` → `"hatsapp.com"` because `lstrip` removes any leading chars in the
set `{w,.}`. The fix is an explicit prefix check. **A `test_config.py` case locks this.**

### The two helpers that keep train and serve honest

```python
FEATURE_WEIGHTS = (0.05, 0.05, 15)   # (char_tfidf, word_tfidf, numeric)

def stack_features(x_char, x_word, x_num):
    from scipy.sparse import hstack
    wc, ww, wn = FEATURE_WEIGHTS
    return hstack([x_char * wc, x_word * ww, x_num * wn]).tocsr()
```
This is the **one place** the three feature blocks are combined. `train_ml_strong.py`, `predict_ml_only.py`
and `fp_sweep.py` all call it, so they can't drift to different weights. *(This is your honest "TF-IDF
is weighted 0.05, numeric 15" talking point — the numbers are right here in the open.)*

```python
def csv_safe(value) -> str:
    s = "" if value is None else str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s      # prefix a quote so Excel treats it as text, not a formula
    return s
```
**CSV-injection guard.** A scanned URL like `=HYPERLINK("http://evil")` written raw into a CSV would
*execute* when a reviewer opens it in Excel. Prefixing a `'` makes it inert text. Used by both the
false-positive log and the Power BI export.

---

## A2. `features.py` — turning a URL into 22 numbers

This is the function the model's "eyes" depend on. `extract_features(url)` returns a **list of exactly
22 numbers**, always in the same order. The order is a *contract* — the model learned "index 11 = @ in
authority," so if you reorder them the model silently breaks. `test_features.py` asserts the length and
pins the security indices.

### Entropy (feature 5) — detecting random-looking hosts

```python
def entropy(url):
    if not url: return 0
    prob = [url.count(c)/len(url) for c in set(url)]
    return -sum(p * math.log(p, 2) for p in prob)
```
Shannon entropy over the characters. A human-readable domain (`paypal.com`) has low entropy; a random
DGA host (`x7g9q2zk.com`) has high entropy. *If asked "what's entropy here?" → "bits of randomness in
the string; phishing throwaway domains look random."*

### The homograph defense (features 20/21 + the brand match)

Two helpers decode internationalized-domain tricks:

```python
def _decode_idn(host):
    # xn--pple-43d.com  →  the Unicode it renders to (an "apple" look-alike)
    out = []
    for label in host.split('.'):
        if label.startswith('xn--'):
            try:    out.append(label[4:].encode('ascii').decode('punycode'))
            except Exception: out.append(label)
        else:       out.append(label)
    return '.'.join(out)

def _skeleton(s):
    # fold Cyrillic/Greek look-alikes to ASCII twins:  'раypal' → 'paypal'
    s = unicodedata.normalize('NFKD', s)
    out = []
    for c in s:
        if c in _CONFUSABLES:   out.append(_CONFUSABLES[c])
        elif ord(c) < 128:      out.append(c)
        # else drop unmappable non-ASCII
    return ''.join(out)
```
`_CONFUSABLES` maps e.g. Cyrillic `а`→`a`, `о`→`o`. So a domain registered with a Cyrillic 'а' that
*looks* like `apple.com` gets reduced to the ASCII skeleton `apple`, which then matches the real brand
in the fuzzy loop below and flags. Real `apple.com` is already ASCII, so its skeleton == itself —
**legit brands are never altered.** `homograph_probe.py` checks 14/14 of these.

### The core feature loop (abridged, with the index comments kept)

```python
url = ensure_scheme(url)              # add http:// only if there's no real scheme://
parsed = urlparse(url)
authority = parsed.netloc            # BEFORE stripping user:pass@  — the @-trick lives here
host = parsed.netloc
if "@" in host: host = host.split("@")[-1]
if ":" in host: host = host.split(":")[0]
if host.startswith("www."): host = host[4:]
…
features.append(len(url)/100)                 # 0  length (scaled)
features.append(url.count('.'))               # 1  dots
features.append(url.count('-'))               # 2  hyphens
features.append(url.count('/'))               # 3  slashes
features.append(sum(c.isdigit() for c in url))# 4  digits
features.append(entropy(url))                 # 5  entropy
kw_count = sum(k in url for k in keywords)
features.append(kw_count)                     # 6  phishing-keyword count
…
features.append(max_sim / 100)                # 7  best fuzzy brand similarity
features.append(brand_spoof_flag)             # 8  looks like a brand but domain != brand
features.append(int(brand_spoof_flag == 1 and kw_count > 0))  # 9 spoof + keyword
features.append(1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0) # 10 IP pattern
features.append(int("@" in authority))        # 11 @ credential trick (authority only!)
…
features.append(int("xn--" in host))                      # 20 punycode present
features.append(int(any(ord(c) > 127 for c in host_idn))) # 21 non-ASCII host
```

Two subtle, *defensible* decisions:
- **Feature 11 uses `authority`, not the whole URL.** An `@` in a query string (`?email=a@b.com`) is
  harmless; an `@` in the authority (`http://paypal.com@evil.com`) is the credential-hiding trick. By
  capturing `authority = parsed.netloc` *before* stripping `user:pass@`, the `@` checks only fire on
  the dangerous case. `test_features.py` has a case for exactly this.
- **The whole function is wrapped in `try/except`** returning `[0] * 22`. A malformed URL can never
  crash the scorer — worst case it scores as all-zeros. The `22` here must match the feature count, and
  a test enforces it.

The fuzzy brand match uses `rapidfuzz.fuzz.ratio` and only accepts matches on pieces ≥ 4 chars with
score > 85, after a `0→o, 1→l, 3→e` leet-normalization — that's what catches `paypa1`, `g00gle`.

---

## A3. `predict_ml_only.py` — the model + the first two gates

This file loads the four pickled artifacts **once** at import and exposes `predict_ml(url)`.

```python
_MODEL_DIR = os.path.dirname(os.path.abspath(__file__))   # anchor on this file
def _load_pkl(name):
    with open(os.path.join(_MODEL_DIR, name), "rb") as fh:
        return pickle.load(fh)

model    = _load_pkl("model.pkl")           # calibrated XGBoost
char_vec = _load_pkl("char_vectorizer.pkl") # 3–5 char n-gram TF-IDF
word_vec = _load_pkl("word_vectorizer.pkl") # word TF-IDF
scaler   = _load_pkl("scaler.pkl")          # StandardScaler for the 22 numbers
```

`predict_ml` returns a **3-tuple** `(prediction, probability, override_reason)` — the `override_reason`
string is how it tells `main.py` *why* it short-circuited (or `None` if the model actually scored it):

```python
def predict_ml(url: str) -> tuple[int, float, str | None]:
    host = parse_host(url)

    # Gate 0a: loopback — PARSED HOST only (not substring)
    if host_is_loopback(host):
        return 0, 0.001, "Localhost dev environment"

    # Gate 0b: trusted-root allowlist (false-positive guard, NOT the detector)
    if _extract_root_domain(host) in TRUSTED_ROOTS:
        return 0, 0.001, "Globally trusted domain"

    # Gate 1: structural certainties — checked BEFORE the ML score
    feats = extract_features(url)
    brand_spoof_corroborated = feats[8] and (feats[9] or feats[16] or feats[20] or feats[21])
    if host_is_ip(host) or feats[11] or brand_spoof_corroborated:
        return 1, 0.999, "Critical: Structural security risk detected"

    # Gate 2: the calibrated model actually scores the URL
    text_url = re.sub(r"^https?://", "", url)       # strip scheme — don't let http/https leak
    Xc = char_vec.transform([text_url])
    Xw = word_vec.transform([text_url])
    Xn = scaler.transform([feats])
    X  = stack_features(Xc, Xw, Xn)                 # SAME weighting helper as training
    prob = float(model.predict_proba(X)[0][1])
    pred = int(prob > ML_DECISION_THRESHOLD)        # threshold 0.60 from rules.json
    return pred, prob, None
```

Things worth being able to defend:
- **`brand_spoof_corroborated`** — a fuzzy brand match (feat 8) *alone* is not enough to hard-flag,
  because a legit name can resemble a brand. It only becomes a decisive override when **corroborated**
  by a keyword (9), suspicious TLD (16) or IDN signal (20/21). Otherwise it falls through to the soft
  model score. This is a deliberate false-positive guard (audit item D4).
- **`_extract_root_domain`** handles two-part TLDs so `bbc.co.uk` → `bbc.co.uk`, not `co.uk`:
  ```python
  _TWO_PART_TLDS = {"co","ac","gov","net","org","edu","com"}
  if len(parts) >= 3 and parts[-2] in _TWO_PART_TLDS:
      return ".".join(parts[-3:]).lower()
  ```
- **The allowlist is an FP guard, not the detector** — the module docstring says so explicitly. The
  model judges everything; the allowlist only exists so it can't *wrongly* flag google.com. And every
  quality probe (`fp_sweep.py`) **bypasses** this file and calls the model directly, so you measure the
  real model, not the allowlist.

---

## A4. `main.py` — the FastAPI server and the 6-gate ladder

This is the file to know cold. The `/predict_url` endpoint is the whole product. The gates run **in a
deliberate order**, and the order is the design.

### Startup: CORS, blocklist, de-fanging

```python
app = FastAPI(title="PhishGuard AI", version="3.2.0")
_cors_origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "*").split(",") if o.strip()] or ["*"]
app.add_middleware(CORSMiddleware, allow_origins=_cors_origins, allow_methods=["*"], allow_headers=["*"])
```
CORS origins come from an **env var** so production can lock it to the Vercel URL without a code change
(defaults to `*` for the local demo).

The input sanitizer de-fangs threat-intel notation so a pasted `hxxp://evil[.]com` is analyzed as a
real URL (and caps length — pathological-input guard):

```python
def _normalize_url(raw: str) -> str:
    u = str(raw or "").strip()
    if len(u) > MAX_URL_LEN: u = u[:MAX_URL_LEN]
    u = re.sub(r"(?i)^hxxp", "http", u)              # hxxp:// → http://
    u = re.sub(r"(?i)\[\s*dot\s*\]", ".", u)         # evil[dot]com → evil.com
    u = (u.replace("[.]", ".")…)
    …
    u = re.sub(r"(?<!:)/{2,}", "/", u)               # collapse // runs, but keep scheme's ://
    return u.strip()
```

The local blocklist is loaded **once** into a `frozenset` for O(1) lookups, from files anchored on the
module path, each read defensively (`except FileNotFoundError: pass` — so a fresh clone without
`phishtank.csv` still boots):

```python
_PHISH_BLOCKLIST = _load_local_blocklist()
print(f"[PhishGuard] local blocklist loaded: {len(_PHISH_BLOCKLIST):,} URL entries")

def check_blocklist(url: str) -> bool:
    return url in _PHISH_BLOCKLIST or url.rstrip("/") in _PHISH_BLOCKLIST
```

### The async/threading pattern (a real engineering point)

CPU work (the model) and blocking I/O (whois/SSL/SQLite) are pushed **off the event loop** so one slow
request can't freeze the server:

```python
pred, prob, override_reason = await asyncio.to_thread(predict_ml, url)   # CPU-bound → thread
…
val = await asyncio.wait_for(asyncio.to_thread(get_domain_age, domain),  # blocking + hard timeout
                             timeout=WHOIS_TIMEOUT_SEC)
```
whois has no built-in timeout and can hang for seconds; `wait_for` bounds it, and a per-domain TTL
cache avoids re-querying. **Logging is wrapped so a DB hiccup can never 500 a good verdict:**

```python
async def _log_event_safe(*args):
    try:
        await asyncio.to_thread(log_event, *args)
    except Exception as e:                 # swallow — logging is a side effect
        print(f"[PhishGuard] log_event failed (non-fatal): {e!r}")
```

### The 6 gates, in order

```python
@app.post("/predict_url")
async def predict_url_endpoint(req: URLRequest):
    url = _normalize_url(req.url)
    if not url: raise HTTPException(400, "URL cannot be empty")
    domain = extract_domain(url)

    # GATE 1 — model scores FIRST
    pred, prob, override_reason = await asyncio.to_thread(predict_ml, url)

    # GATE 2 — structural certainty (raw IP / @ / corroborated spoof) → PHISHING 10.0
    if override_reason and "Critical" in override_reason:
        … return PHISHING, score 10.0

    # GATE 2b — exact known-phishing blocklist hit → PHISHING 9.0
    #   runs BEFORE the safe fast-path, and overrides the allowlist ONLY for shared hosts
    _shared_host_allowlisted = (override_reason == "Globally trusted domain"
                                and is_shared_hosting_host(domain))
    if check_blocklist(url) and (override_reason is None or _shared_host_allowlisted):
        … return PHISHING, score 9.0

    # GATE 2c — trusted-root allowlist survived the blocklist → honor SAFE
    if override_reason == "Globally trusted domain":
        … return SAFE, score round(prob*3, 2)

    # GATE 3 — model confident-safe + no cheap local flag → fast SAFE (no SSL/whois)
    if pred == 0 and prob < ML_SAFE_THRESHOLD:
        typo_flag, _ = check_typo(domain)
        sub_flag,  _ = check_subdomain(url)
        brand_flag   = any(b in domain and not is_legit_brand_domain(domain, b) for b in BRANDS)
        if not (typo_flag or sub_flag or brand_flag):
            … return SAFE, score round(prob*3, 2)

    # GATE 4 — the model is uncertain → full weighted heuristics (+ dampener)
    age, ssl_valid = await asyncio.gather(_age_async(domain), _ssl_async(domain))
    score = prob * 3
    if brand_flag:   score += W_BRAND;    reasons.append("Brand impersonation in domain")
    if typo_flag:    score += W_TYPO;     …
    if keyword_flag: score += W_KEYWORD;  …          # only if prob ≥ KEYWORD_MIN_PROB (0.55)
    if age < NEW_DOMAIN_MAX_AGE_DAYS: score += W_NEW_DOMAIN; …
    if not ssl_valid: score += W_NO_SSL; …
    if prob < DAMPENER_THRESHOLD:
        score *= 0.5                                  # model says safe → halve heuristic noise
        reasons.append("Heuristics dampened: ML confident site is safe")
    if score > T_PHISHING:      result = "PHISHING"
    elif score >= T_SUSPICIOUS: result = "SUSPICIOUS"
    else:                       result = "SAFE"
```

**Why the order is the whole design — the four questions an interviewer asks:**

1. *"Why is the blocklist (2b) before the safe fast-path (3)?"* Because the dangerous case is a
   benign-looking host the model scores ~0 (a weaponized `github.io` clone). If the safe path ran
   first it would return SAFE and the blocklist would never get a say. So the decisive reputation
   signal is checked first.
2. *"Why does the blocklist override the allowlist only for shared hosts?"* `github.io` is on the
   allowlist as an FP guard, but its trust belongs to the *platform*, not the tenant — so a specific
   blocklisted `evil.github.io/login` page should flip, while `google.com` (a real brand root, never
   "shared") can never be flipped by a stale feed entry.
3. *"What's Gate 2c for?"* It fixes a real FP: `microsoft.github.io` read as a brand-in-subdomain
   trick and the Gate-4 heuristics dragged it to SUSPICIOUS. Honoring the allowlist's SAFE verdict
   *before* Gate 4 restores the promise "a trusted root is never wrongly flagged."
4. *"What's the dampener?"* When the model is confident-safe (`prob < DAMPENER_THRESHOLD`) but a weak
   heuristic still fired, halve the heuristic score so lexical noise can't tip a site the model trusts.

Also defensible: **the keyword bump only corroborates** (`prob >= KEYWORD_MIN_PROB`, 0.55). At 0.40 it
pushed real `/login` and `/account` pages over the line; raising it to 0.55 cut real-site false alarms
~15% for a measured recall cost of 13-in-8000 (which the blocklist also covers). That number came from
`keyword_rule_probe.py` — a *measured* trade, not a guess.

---

## A5. `url_augment.py` — the helper that kills the leakage artifact

This small module is the technical heart of the leakage fix. Two functions matter.

```python
def registrable_domain(url: str) -> str:
    host = _host_of(url)
    if host.startswith("www."): host = host[4:]
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in _TWO_PART_TLDS:
        return ".".join(parts[-3:])          # bbc.co.uk
    return ".".join(parts[-2:]) if len(parts) > 1 else host
```
This is the **group key** for the split. Everything with the same registrable domain goes entirely into
train *or* test — never both. That's what makes the ~74% honest.

```python
def add_path(url, rng=None):
    rng = rng or random
    base = strip_to_host(url).rstrip("/")
    if rng.random() < 0.35:                   # 35% of the time: a DEEP stacked path
        depth = rng.randint(2, 7)
        segs = [rng.choice(DEEP_SEGMENTS) for _ in range(depth)]
        return base + "/" + "/".join(segs)    # e.g. /login/verify/account/secure/update
    path = rng.choice(PATH_POOL)
    …
    return base + path
```
Called on **both classes** at training time. Because legit and phishing URLs get paths drawn from the
*same* pool at the *same* rate, "has a path" and "path is deep/keyword-stacked" carry **no label
signal** — only the host does. The deep-path rate was raised 0.15→0.35 (v3.4) specifically because
non-allowlisted legit hosts (vedantu.com) rarely saw deep paths in training, so a pathological
`/login/verify/account/…` tipped them over. `parent_path_probe.py` went 5/9 → 0/9 after the fix.

---

## A6. `database.py` — SQLite logging and stats

One table, `phishing_events`. Three functions: `log_event`, `get_stats`, `get_recent_events`. Every
connection uses `contextlib.closing` so handles can't leak:

```python
def log_event(type_, content, result, risk_score, response_time=0):
    with closing(_get_conn()) as conn:
        conn.execute("INSERT INTO phishing_events (...) VALUES (?,?,?,?,?,?)",
                     (type_, content[:500], result, round(risk_score,4),
                      round(response_time,4), datetime.datetime.utcnow().isoformat()))
        conn.commit()
```
- **Parameterized query (`?` placeholders)** — never string-formatted — so a URL can't SQL-inject.
- `content[:500]` caps stored length. `DB_PATH` comes from an env var (`PHISHGUARD_DB`), so the docstring's
  "swap to postgres for prod" is a one-line change.
- `get_recent_events` coerces/clamps `limit` to `max(0, int)` because a **negative LIMIT in SQLite means
  "no limit"** — which would dump the whole table. Clamped at both the API edge and here (defense in depth).
- `init_db()` runs on import, creating the table and two indexes if absent — so a fresh clone just works.

---

# PART B — The training & measurement files

## B1. `train_ml_strong.py` — how `model.pkl` is built (9 steps)

The docstring is itself an audit trail of the leakage fixes. The nine steps in code:

**1 & 2 — load, then drop label noise.** Trusted roots can never be phishing examples; shorteners/
free-hosts are dropped from both classes (one root = many unrelated sites = noise):

```python
phishing = phishing[~phishing["root"].isin(TRUSTED_ROOTS)]        # (a)
legit    = legit[~legit["root"].isin(NOISE_ROOTS)]                 # (b)
phishing = phishing[~phishing["root"].isin(NOISE_ROOTS)]
```
Rule **(c)** — dropping phishing whose root appears in the legit set — was *tried and reverted*; the
comment records that it pushed FP 10.4%→13.8%. That reverted-with-evidence comment is gold in an
interview: it shows you measure, not guess.

**3 — balance 50/50, cap, then augment** (the core fix):

```python
size = min(len(phishing), len(legit), MAX_PER_CLASS)      # 150k cap
…
for u, lab in zip(data["url"], data["label"]):
    bare = strip_to_host(u)
    aug_urls.append(bare);             aug_labels.append(lab)   # bare copy
    aug_urls.append(add_path(u, rng)); aug_labels.append(lab)   # pathed copy
```
A sanity print then confirms **both** classes end up ~50% pathed — proof the artifact is gone.

**4 — the grouped 3-way split, taken on ROW INDICES before any fitting:**

```python
groups = original_urls.apply(registrable_domain).values
gss_test = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=SEED)
trainval_idx, test_idx = next(gss_test.split(idx_all, labels, groups))
# then split trainval again → train_idx, cal_idx
assert g_train.isdisjoint(g_test),  "LEAKAGE: train/test share a domain"
assert g_train.isdisjoint(g_cal),   "LEAKAGE: train/calibrate share a domain"
assert g_cal.isdisjoint(g_test),    "LEAKAGE: calibrate/test share a domain"
```
Those three `assert … isdisjoint()` lines make leakage a **hard crash**, not a silent inflation.

**5 — fit vectorizers + scaler on TRAIN ONLY** (the v3.5 M10 fix), then transform the other slices:

```python
char_vec.fit(train_text); word_vec.fit(train_text)      # train rows only
scaler.fit(X_num_all[train_idx])
def _build(slice_idx):
    return stack_features(char_vec.transform(...), word_vec.transform(...),
                          scaler.transform(X_num_all[slice_idx]))
```
Previously the vectorizers were fit on the *full* set before the split — so the transform had "seen"
the test rows and the score was mildly optimistic. Now it's leakage-free end to end.

**6 & 7 — stack with the shared weights, train deterministic XGBoost:**

```python
base_model = XGBClassifier(n_estimators=400, max_depth=7, learning_rate=0.05,
                           eval_metric="logloss",
                           random_state=SEED, n_jobs=1,   # M11: bit-reproducible
                           verbosity=0)
base_model.fit(X_train, y_train)
```
`n_jobs=1` + `random_state=SEED` make the run reproducible (XGBoost's parallel histogram build is
otherwise order-nondeterministic) — which is what makes the golden-score tests a real lock.

**8 — calibrate on the DISJOINT calibration slice** (fixes the old leak where calibration was fit on
the test set):

```python
model = CalibratedClassifierCV(base_model, cv="prefit", method="isotonic")
model.fit(X_cal, y_cal)      # disjoint from both train and test
```

**9 — pickle the four artifacts.** Those exact four files are what `predict_ml_only.py` and `fp_sweep.py`
load. Train and serve now agree by construction.

## B2. `fp_sweep.py` — the gate that every retrain must pass

The whole point: score the **model alone** (allowlist + rules bypassed) over 80,110 known-legit URLs
and count how many it wrongly flags.

```python
model, char_vec, word_vec, scaler = (_load(...) for ...)      # from a dir arg → compare versions
text = [re.sub(r"^https?://", "", u) for u in urls]
X = stack_features(char_vec.transform(text), word_vec.transform(text),
                   scaler.transform(np.array([extract_features(u) for u in urls])))
probs = model.predict_proba(X)[:, 1]
fp = int((probs > THR).sum())
print(f"  Model false positives : {fp:,}  ({fp / n * 100:.2f}%)")
```
- It takes a **model directory as `argv[1]`**, so you can run it against a backup dir and the live model
  on the *identical* URL set — a fair A/B. That's how "FP 6.91% → 6.23%" is a real comparison.
- It builds the matrix with the **same `stack_features`** as training — no drift.
- v3.5 result: **6.23%**, under the **9.70% ceiling**. If a retrain exceeds the ceiling, you revert.
  This is the single number the whole retrain discipline gates on.

The other probes follow the same shape (load model → score a labeled set → print a rate): `cross_source_recall_probe.py`
(70.4% on unseen OpenPhish), `homograph_probe.py` (14/14), `operating_point.py` (compare versions at
*equal FP*), `parent_path_probe.py` (0/9 after the path fix). **Probes own the quality numbers; pytest
owns the behavioral contracts** — two different jobs.

---

# PART C — The Chrome extension (the security-fix story)

## C1. `extension/background.js` — MV3 service worker, two bugs fixed

The service worker watches tab navigations and, on a PHISHING verdict, injects a warning banner. Both
security fixes live here.

```javascript
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  const url = tab.url;
  if (shouldSkip(url)) return;                 // chrome://, file://, data:, …
  const data = await checkUrl(url);            // POST /predict_url (cached + timeout)
  if (!data) return;
  setBadge(tabId, data.result);                // ✓ / ⚠ / ⛔
  if (data.result === "PHISHING")
    injectWarning(tabId, data.risk_score || 0, data.reasons || []);
});
```

**Fix 1 — CSP (`new Function` → `chrome.scripting`).** MV3's service-worker CSP blocks `eval`/`new
Function`, so the old banner code *never ran*. The banner is now injected as a **serializable function
+ args**, which Chrome re-parses safely in the page:

```javascript
async function injectWarning(tabId, score, reasons) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: renderBanner,                                  // a real function, not a code string
      args: [Number(score) || 0, Array.isArray(reasons) ? reasons.slice(0, 3) : []],
    });
  } catch { /* some pages block scripting (Web Store) — ignore */ }
}
```

**Fix 2 — DOM-XSS (`innerHTML` → `textContent`).** The banner text includes server-supplied `reasons`,
which can echo an attacker-controlled URL. Building the DOM with `createElement` + `textContent` means
that string is **never parsed as HTML** — no markup/script injection possible:

```javascript
function renderBanner(score, reasons) {
  if (document.getElementById("phishguard-banner")) return;  // idempotent
  const bar = document.createElement("div");
  bar.id = "phishguard-banner";
  …
  reasons.slice(0, 3).forEach((r) => {
    const li = document.createElement("li");
    li.textContent = `→ ${r}`;     // textContent, NOT innerHTML — the fix
    list.appendChild(li);
  });
  …
}
```

`checkUrl` caches results and uses `fetchWithTimeout` (from `config.js`) so a dead backend never hangs
the badge logic — it just fails silently. The popup (`popup.js`) is the manual-check UI and shares the
same `config.js` helpers so popup and worker behave identically.

---

# PART D — The frontend & the rest (brief)

- **`frontend/js/env.js`** sets `window.PHISHGUARD_API_BASE` — the single deploy override, loaded
  *before* `config.js`. Empty = fall back to localhost. This is why the same static files run locally
  and on Vercel pointing at Render.
- **`frontend/js/config.js`** reads `window.PHISHGUARD_API_BASE` first, then `localStorage`, then
  localhost — so the API base is runtime-configurable with no rebuild.
- **`export_to_bi.py`** flattens `phishing_events` into a CSV star-schema (fact + date/result/domain
  dimensions) for Power BI, running every cell through `csv_safe`.
- The **data-builder scripts** (`build_dataset.py`, `build_legit_dataset.py`, `generate_adversarial.py`,
  `harvest_fresh_data.py`, `refresh_feeds.py`) are offline one-shots that produce the CSVs in Map 2.
  You don't need them at serve time. Doc 09 lists every one.

---

# The end-to-end trace (say this to "walk me through what happens on a scan")

Paste `paypa1-login.tk/account` into the web app and hit check:

1. **Frontend** POSTs `{"url": "paypa1-login.tk/account"}` to `/predict_url` (base from `env.js`).
2. **`_normalize_url`** trims it, de-fangs nothing here, collapses slashes.
3. **Gate 1** → `asyncio.to_thread(predict_ml, url)`:
   - `parse_host` → `paypa1-login.tk`. Not loopback, not a trusted root.
   - `extract_features` → feat 7 fuzzy-matches `paypal` (after `1→l` leet-fold) so feat 8 = 1; feat 16
     = 1 (`.tk` is a suspicious TLD). `brand_spoof_corroborated` = True.
   - Returns `(1, 0.999, "Critical: Structural security risk detected")`.
4. **Gate 2** sees `"Critical"` in the reason → **PHISHING, score 10.0**, reasons = that string.
5. `_log_event_safe` writes the event to SQLite off the event loop; the JSON response goes back.
6. The **extension**, had you merely browsed there, would get the same verdict, set the ⛔ badge, and
   `chrome.scripting` the red banner into the page via `textContent`.

A *legit* URL (`https://github.com/user/repo`) instead: Gate 1 model scores it low → not Critical →
not blocklisted → `github.com`… actually `github.io` is the shared host; `github.com` is a normal root,
so it flows to **Gate 3**, the model is confident-safe, no typo/subdomain/brand flag fires → **SAFE in
milliseconds**, no whois/SSL call made.

---

## The one-paragraph recap

`rules.json` holds every tunable; `config.py` loads it once and exposes the constants plus the shared
host-parsing and feature-stacking helpers. `features.py` turns a URL into 22 ordered numbers (with
homograph decoding). `predict_ml_only.py` loads the calibrated-XGBoost artifacts and runs loopback →
allowlist → structural → model. `main.py` wraps that in a 6-gate ordered ladder (model → structural →
blocklist → allowlist-SAFE → confident-safe → weighted heuristics+dampener), with all slow work pushed
off the event loop and logging that can't 500 a verdict. `database.py` records every scan. The model is
built by `train_ml_strong.py` with the leakage fixes (grouped split, train-only fit, path
decorrelation, deterministic + calibrated), and `fp_sweep.py` is the 9.70%-FP gate every retrain must
clear. The Chrome extension consumes the same API and had its two security bugs (CSP eval, DOM-XSS)
fixed. **That's the whole system — and every claim here points at a line you can open.**
