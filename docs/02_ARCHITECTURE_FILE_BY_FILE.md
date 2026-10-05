# 02 — Architecture, File-by-File, and the Request→Response Lifecycle

This document explains **every file** in the project, then traces the **exact path a request
takes** from the moment you click "Check" to the verdict appearing on screen.

---

## Part A — The repository, file by file

```
phishguard-ai/
├── backend/                  ← the FastAPI service + all ML code
│   ├── main.py               ← THE API. Endpoints + the 6-gate serving ladder
│   ├── predict_ml_only.py    ← model inference (loads artifacts, returns prob + override)
│   ├── features.py           ← the 22 URL features (+ homograph/IDN decoding)
│   ├── config.py             ← all thresholds/weights + host-parsing helpers + stack_features()
│   ├── rules.json            ← the tunable data: brands, keywords, TLDs, trusted roots, scoring
│   ├── database.py           ← SQLite logging + stats queries
│   ├── train_ml_strong.py    ← the training pipeline (produces the 4 model artifacts)
│   ├── url_augment.py         ← path-decorrelation augmentation used during training
│   ├── export_to_bi.py       ← SQLite → star-schema CSVs for Power BI
│   ├── refresh_feeds.py      ← pull live OpenPhish/PhishTank into the local blocklist
│   ├── harvest_fresh_data.py ← mine novel+clean phishing domains (fed v3.3+)
│   ├── model.pkl             ← trained calibrated XGBoost   ┐
│   ├── char_vectorizer.pkl   ← char 3–5 gram TF-IDF          │ the 4 serving
│   ├── word_vectorizer.pkl   ← word TF-IDF                   │ artifacts
│   ├── scaler.pkl            ← StandardScaler (22 features)  ┘
│   ├── tests/                ← the 128-case offline pytest suite
│   └── *_probe.py, fp_sweep.py, operating_point.py ← statistical model-quality tools
│
├── frontend/                 ← the static web app (no build step)
│   ├── index.html            ← landing page
│   ├── url-checker.html      ← the URL checker UI
│   ├── dashboard.html        ← analytics dashboard UI
│   ├── extension.html        ← extension install guide
│   ├── js/env.js             ← deploy-time backend URL override
│   ├── js/config.js          ← API base resolution + fetchWithTimeout
│   ├── js/checker.js         ← checker page logic (calls /predict_url)
│   ├── js/dashboard.js       ← dashboard logic (calls /stats)
│   └── css/styles.css        ← all styling
│
├── extension/                ← the Chrome MV3 extension
│   ├── manifest.json         ← MV3 manifest (permissions, service worker, popup)
│   ├── background.js         ← service worker: checks pages, injects warning banner
│   ├── config.js             ← API base + bounded cache + fetchWithTimeout
│   ├── popup.html / popup.js ← the toolbar popup (verdict for the current tab)
│
├── data/raw/                 ← raw threat feeds (openphish.txt committed; others gitignored)
├── analytics/                ← Power BI CSV exports (generated)
├── docs/                     ← THIS documentation set
├── MODEL_AUDIT.md            ← the canonical retrain changelog (v3.0→v3.5)
├── DEPLOY.md                 ← deployment guide
├── render.yaml               ← Render backend blueprint
├── vercel.json               ← Vercel frontend config
└── requirements.txt          ← Python dependencies
```

### A.1 `backend/main.py` — the API and the decision ladder

This is the spine of the system. It:
- Creates the FastAPI app and configures **CORS** (env `CORS_ORIGINS`, `*` for the demo).
- Loads the **local blocklist** once at startup (`openphish.txt` + `phishtank.csv` → a
  `frozenset` for O(1) membership).
- Defines `_normalize_url()` — the input-hardening step (de-fang, cap length, collapse slashes).
- Defines the endpoints and the **6-gate serving ladder** inside `predict_url_endpoint`.

**Endpoints:**
| Method + path | Purpose |
|---|---|
| `POST /predict_url` | The main one. Body `{ "url": "..." }` → verdict + score + reasons + meta |
| `POST /report_false_positive` | User reports a wrong verdict → appended to a log for review |
| `GET /stats` | Aggregated KPIs for the dashboard (counts, rates, daily breakdown, top threats) |
| `GET /recent` | Recent scan events (bounded) |
| `GET /health` | Liveness + versions: `{status, version 3.2.0, model v3.5, decision_threshold 0.6, keyword_min_prob 0.55}` |
| `GET /` | Root banner |

**Environment variables it reads:** `CORS_ORIGINS`, `FP_LOG_PATH` (false-positive log),
`RAW_FEED_DIR` (where the blocklist files live), `PHISHGUARD_DB` (SQLite path).

The gate ladder is the detection logic and is documented fully in
[04_RULES_AND_DETECTION_LOGIC.md](04_RULES_AND_DETECTION_LOGIC.md); the request-flow section
below walks one request through it.

### A.2 `backend/predict_ml_only.py` — model inference

The "Gate 1" brain. On import it **loads the four artifacts** (`model.pkl`,
`char_vectorizer.pkl`, `word_vectorizer.pkl`, `scaler.pkl`), anchored on `__file__` so it works
regardless of the process's working directory.

Its function `predict_ml(url)` returns a triple `(pred, prob, override_reason)`:
1. **Loopback/localhost** → `(0, 0.001, "Localhost dev environment")` — dev URLs are never phishing.
2. **Registrable root in `TRUSTED_ROOTS`** → `(0, 0.001, "Globally trusted domain")` — the
   allowlist safety net.
3. **Structural-critical** — raw-IP host, `@` in the authority, or a **corroborated brand spoof**
   (`feats[8]` brand look-alike AND one of: keyword `feats[9]`, suspicious TLD `feats[16]`,
   punycode `feats[20]`, non-ASCII host `feats[21]`) → `(1, 0.999, "Critical: Structural security
   risk detected")`.
4. **Otherwise the actual model** — extract 22 features, TF-IDF transform, `stack_features()` to
   apply the `[0.05, 0.05, 15]` block weights, then
   `prob = model.predict_proba(X)[0][1]`, `pred = int(prob > 0.60)`.

`override_reason` is the crucial channel that tells `main.py` **why** the model shortcut — the
serving ladder branches on it (e.g. an allowlist SAFE vs a genuine model score).

### A.3 `backend/features.py` — the 22 features

Turns a URL string into a length-22 numeric vector. Indices 0–21 are enumerated exhaustively in
[03_MACHINE_LEARNING_FROM_BASICS.md](03_MACHINE_LEARNING_FROM_BASICS.md#the-22-features). It also
holds the **homograph machinery**: `_decode_idn` (decode `xn--` punycode), `_CONFUSABLES` +
`_skeleton` (map look-alike Cyrillic/Greek characters to ASCII twins), and the rapidfuzz brand
fuzzy match. On any exception it returns `[0]*22` so a weird URL never crashes inference.

### A.4 `backend/config.py` — thresholds, weights, and safe helpers

The single place that:
- Loads `rules.json` and exposes every threshold/weight as a Python constant
  (`ML_SAFE_THRESHOLD 0.35`, `ML_DECISION_THRESHOLD 0.60`, `W_BRAND 3.0`, `T_PHISHING 4.5`, …).
- Holds **`FEATURE_WEIGHTS = (0.05, 0.05, 15)`** and **`stack_features()`** — the single source of
  truth for how char/word/numeric blocks are weighted and stacked. Both training and serving call
  this, so they can **never drift** (this was the H3 fix).
- Provides **security-critical host helpers**: `strip_www`, `ensure_scheme`, `parse_host`,
  `host_is_ip`, `host_is_loopback`, and `csv_safe`. These parse the **actual host** rather than
  doing substring checks on the raw URL — closing a class of bypasses (e.g. `localhost` appearing
  in a path shouldn't make a URL look like localhost).
- Asserts an **invariant**: `SHARED_HOSTING_ROOTS ⊆ TRUSTED_ROOTS` (so the shared-host carve-out
  can actually fire).

### A.5 `backend/rules.json` — the tunable data (no code change to edit)

Pure data so lists can grow without touching code:
- **brands** (32): google, paypal, microsoft, amazon, … irctc.
- **keywords** (41): login, verify, secure, account, update, … customer.
- **suspicious_tlds** (19): xyz, ru, tk, ml, ga, cf, pw, gq, top, zip, mov, icu, sbs, cam, rest,
  click, win, gdn, cyou.
- **trusted_roots** (~245): global brands + a strong Indian banking/gov/edu set (sbi.co.in,
  irctc.co.in, byjus.com, …).
- **shared_hosting_roots** (7): github.io, blogspot.com, wordpress.com, readthedocs.io,
  workers.dev, ghost.io, tumblr.com.
- **scoring**: every threshold and weight (see doc 04).
- **network**: WHOIS 4 s, SSL 5 s, cache TTL 900 s.
- **limits**: MAX_URL_LEN 2048, NEW_DOMAIN_MAX_AGE_DAYS 30, RECENT_MAX_LIMIT 200.

### A.6 `backend/database.py` — the event log

SQLite via stdlib `sqlite3`. One table, auto-created on import:
```
phishing_events(id, type, content, result, risk_score, response_time, timestamp)
```
with indexes on `timestamp` and `result`. Functions: `log_event()` (write one detection),
`get_stats()` (the dashboard KPIs incl. daily breakdown and top threats), `get_recent_events()`.
DB path is env-configurable (`PHISHGUARD_DB`), defaulting to `phishguard.db`.

### A.7 `backend/train_ml_strong.py` — the training pipeline

Produces the four artifacts. Loads the datasets, applies label-noise cleaning (A5), augments URLs
with **path decorrelation** (so "has a path" carries no class signal), takes a **GroupShuffleSplit
by registrable domain**, fits the vectorizers + scaler **on the train slice only** (M10),
trains a deterministic **XGBoost** (M11: `random_state=42, n_jobs=1`), and **isotonic-calibrates**
on a disjoint slice. Fully explained in doc 03.

### A.8 `backend/url_augment.py` — training-time path augmentation

Builds realistic and pathological paths and attaches them to **both** classes at train time, so
path depth/keywords don't correlate with the label. `add_path` emits a deep 2–7-segment path 35%
of the time (the v3.4 fix). Helpers: `registrable_domain` (handles two-part TLDs like `.co.uk`),
`has_path`, `strip_to_host`.

### A.9 The support/analytics scripts

- **`export_to_bi.py`** — SQLite → `analytics/*.csv` star schema for Power BI (fact + 3 dims +
  KPI summary), CSV-injection-safe.
- **`refresh_feeds.py`** — pulls the **live** OpenPhish feed (and PhishTank if a key is set) and
  unions fresh live URLs into the local blocklist (timestamped backup, atomic write, network
  failure leaves the file untouched).
- **`harvest_fresh_data.py`** — mines the Phishing.Database ACTIVE list for **novel + clean** bare
  phishing roots (the v3.3 data upgrade).
- **The probes** (`fp_sweep.py`, `operating_point.py`, `cross_source_recall_probe.py`,
  `homograph_probe.py`, `parent_path_probe.py`, `byjus_pathfix_probe.py`, `model_stress_test.py`,
  `fresh_recall_probe.py`, `keyword_rule_probe.py`) — statistical model-quality measurement. These
  own the accuracy/FP/recall numbers; the pytest suite owns the behavioral contracts. Detailed in
  doc 06.

### A.10 Frontend files

- **`index.html`** — landing/marketing page.
- **`url-checker.html`** — the checker: an input, a Check button, example URLs, a results area,
  and a "How URL detection works" explainer. Loads `env.js` → `config.js` → `checker.js`.
- **`dashboard.html`** — the analytics view; loads `env.js` → `config.js` → `dashboard.js`.
- **`extension.html`** — how to install the packaged extension (`phishguard-extension.zip`).
- **`js/env.js`** — sets `window.PHISHGUARD_API_BASE` (currently the Render URL). Loaded first.
- **`js/config.js`** — resolves the API base (`window.PHISHGUARD_API_BASE` → `localStorage` →
  `http://localhost:8000`) and provides `fetchWithTimeout` (10 s).
- **`js/checker.js`** — reads the input, POSTs `/predict_url`, renders the result card with
  **every field escaped** (`escapeHtml`), holds the EXAMPLES list.
- **`js/dashboard.js`** — GETs `/stats` and renders KPIs/charts.

### A.11 Extension files — see [05_CHROME_EXTENSION.md](05_CHROME_EXTENSION.md).

### A.12 Deploy/config files

- **`render.yaml`** — Render blueprint: `rootDir: backend`, Python 3.12.1, build
  `pip install -r requirements.txt`, start `uvicorn main:app --host 0.0.0.0 --port $PORT`,
  health check `/health`, `CORS_ORIGINS` env, free tier.
- **`vercel.json`** — `outputDirectory: frontend`, no build command, `cleanUrls: true`.
- **`DEPLOY.md`** — step-by-step: backend on Render → frontend on Vercel → lock CORS.

---

## Part B — The request→response lifecycle (the exact path)

This is the "how does a request happen and how is it responded" walkthrough. We follow **one URL**
from the checker page all the way to the rendered verdict.

### Step 0 — Page load (one-time setup)

`url-checker.html` loads three scripts **in order**:
1. `env.js` sets `window.PHISHGUARD_API_BASE = "https://phishguard-backend-ihvp.onrender.com"`.
2. `config.js` computes `API_BASE` from that (this is why order matters), and defines
   `fetchWithTimeout`.
3. `checker.js` wires the Check button and renders example chips.

### Step 1 — The user acts

The user types `http://paypa1.com@secure-update.xyz/login` and clicks **Check** (or presses
Enter). `checker.js`'s `check()` runs.

### Step 2 — The client sends the request

`checker.js` calls:
```
POST  {API_BASE}/predict_url
Content-Type: application/json

{ "url": "http://paypa1.com@secure-update.xyz/login" }
```
wrapped in `fetchWithTimeout` (10 s). If the backend is cold (Render nap), the timeout fires and
the UI shows a friendly "could not reach the API, retry" message rather than hanging.

**What physically happens on the wire:** the browser makes an HTTPS request to the Render host.
Because the frontend (Vercel origin) and backend (Render origin) differ, this is a
**cross-origin** request — which is why the backend sets **CORS** headers (`CORS_ORIGINS`). The
browser first may send a **preflight `OPTIONS`** request; FastAPI's CORS middleware answers it,
then the real POST goes through.

### Step 3 — FastAPI receives and validates

The request hits `predict_url_endpoint`. **Pydantic** validates the body shape (`url` is a
string); a malformed body would get an automatic `422` here. A timer starts (for `response_time`).

### Step 4 — Input normalization (`_normalize_url`)

Before any detection, the URL is hardened:
- **De-fang** threat-intel notation: `hxxp://` → `http://`, `[.]`/`[dot]`/`(.)` → `.`, strip stray
  brackets. (Analysts share malicious URLs de-fanged; this makes them live again for analysis.)
- **Collapse redundant slashes** `(?<!:)/{2,}` → `/` (so `byjus.com//////login` can't inflate
  path-based features), preserving `://`.
- **Cap length** at 2048 chars (DoS/abuse guard).

### Step 5 — GATE 1: the ML model scores the URL

`main.py` calls, **off the event loop** so it can't stall the server:
```python
pred, prob, override_reason = await asyncio.to_thread(predict_ml, url)
```
Inside `predict_ml` (see A.2): it checks loopback → allowlist → structural-critical, and if none
of those short-circuit, it runs the real pipeline:
1. `features.extract_features(url)` → the 22-vector (here: `@`-in-authority sets `feats[11]=1`,
   `paypa1` fuzzy-matches `paypal` so `feats[8]=1`, `.xyz` is a suspicious TLD so `feats[16]=1`).
2. char + word TF-IDF transforms of the URL string.
3. `config.stack_features(...)` applies the `[0.05, 0.05, 15]` weights and `hstack`es to one row.
4. `model.predict_proba(X)[0][1]` → the calibrated phishing probability.

For **this** URL, the `@`-in-authority (`feats[11]`) is a structural-critical signal, so
`predict_ml` returns `(1, 0.999, "Critical: Structural security risk detected")` **before** even
needing the soft score.

### Step 6 — GATES 2→4: the rule ladder interprets the model output

The ladder runs in strict order (full logic in doc 04). For our example it stops almost
immediately:
- **Gate 2** — `override_reason` contains `"Critical"` → verdict **PHISHING**, risk **10.0**,
  reason "Structural security risk (credential-hiding `@`)". Done.

For a *different* URL the flow would continue:
- **Gate 2b** — exact match in the local blocklist → **PHISHING** (risk 9.0), unless an allowlist
  root owns it (except the shared-hosting carve-out).
- **Gate 2c** — `override_reason == "Globally trusted domain"` → **SAFE** (allowlist integrity).
- **Gate 3** — model is confidently safe (`pred==0 and prob<0.35` and no typo/subdomain/brand
  flag) → **SAFE** fast path.
- **Gate 4** — otherwise compute a weighted score: `score = prob*3` + `W_BRAND`/`W_TYPO`/
  `W_SUBDOMAIN`/`W_IP`/`W_KEYWORD` (keyword only if `prob ≥ 0.55`) + optional live signals, with a
  **confidence dampener** (`×0.5` if `prob < 0.3`), then threshold: `≥ 4.5` PHISHING, `≥ 3.0`
  SUSPICIOUS, else SAFE.

### Step 7 — Enrichment (optional, non-blocking reasons)

For borderline cases the backend may add optional signals — domain age via WHOIS (≤ 4 s,
cached), SSL info — purely to enrich the **reasons** list. These **never gate** the verdict and
degrade to "unknown" on timeout, so a slow WHOIS can't slow down or 500 the response.

### Step 8 — Log the event (off the event loop)

The verdict is written to SQLite via `database.log_event(...)`, again through
`asyncio.to_thread` so a DB hiccup can't 500 the verdict. This row later feeds `/stats`,
`/recent`, and the Power BI export.

### Step 9 — The JSON response

FastAPI serializes and returns something like:
```json
{
  "url": "http://paypa1.com@secure-update.xyz/login",
  "result": "PHISHING",
  "risk_score": 10.0,
  "reasons": [
    "Credential-hiding '@' in the host authority",
    "Brand look-alike: 'paypa1' resembles 'paypal'",
    "Suspicious top-level domain: .xyz"
  ],
  "ml_probability": 0.999,
  "domain_age_days": -1,
  "ssl_valid": null,
  "response_time_ms": 7.4
}
```
CORS headers accompany it so the Vercel-origin page is allowed to read it.

### Step 10 — The client renders the verdict

`checker.js`'s `renderResultCard()`:
- Picks the color/label from the verdict (`PHISHING` = red).
- **Escapes every string** (`escapeHtml`) — the URL and each reason are attacker-controlled, so
  they're inserted as text, never as HTML, preventing DOM-XSS.
- Shows the risk score, the reasons list, and the meta (ML probability, response time).

The whole round trip is typically **single-digit to low-tens of milliseconds** once the backend is
warm (the model inference is sub-millisecond; most of the time is network + optional lookups).

### The dashboard path (a second, simpler flow)

`dashboard.html` → `dashboard.js` does `GET {API_BASE}/stats`; `main.py` calls
`database.get_stats()` which runs aggregate SQL over `phishing_events` and returns KPIs (total
scans, phishing/suspicious/safe counts, detection rate, avg response time, daily breakdown, top
threats). `dashboard.js` renders them. `GET /recent` similarly lists recent events.

### The extension path (a third flow)

The Chrome extension's service worker calls the **same** `POST /predict_url` for each page you
visit (with a local cache to avoid re-checking), and injects a warning banner if the verdict is
bad. Same backend, same ladder — detailed in [05_CHROME_EXTENSION.md](05_CHROME_EXTENSION.md).

---

## Part C — How everything is connected (the dependency picture)

```
rules.json ──loaded by──▶ config.py ──imported by──▶ features.py
                              │                          │
                              │                          ▼
                              ├───────────────▶ predict_ml_only.py ──uses──▶ model.pkl + 3 vectorizers
                              │                          │
                              ▼                          ▼
                          main.py  ◀───────────── (Gate 1 calls predict_ml)
                              │
                 ┌───────────┼─────────────┐
                 ▼           ▼             ▼
           database.py   CORS/HTTP     asyncio.to_thread
           (SQLite)      (clients)     (off-loop work)
                 │
                 ▼
           export_to_bi.py ──▶ analytics/*.csv ──▶ Power BI

train_ml_strong.py ──(offline, produces)──▶ model.pkl + char/word vectorizers + scaler.pkl
        ▲
        └── uses url_augment.py, features.py, config.stack_features()  (SAME weights as serving)
```

The key connections to state in an interview:
- **`config.stack_features()` is called by *both* `train_ml_strong.py` and `predict_ml_only.py`** —
  so the feature geometry at training exactly equals the geometry at serving. This is why the
  golden-score tests are meaningful.
- **`rules.json` → `config.py`** is the one place thresholds live; `features.py`, `predict_ml_only.py`,
  and `main.py` all read from `config`, so a tuning change is one edit.
- **The four `.pkl` artifacts are the frozen output of training**, committed to the repo so the
  server needs no training step to run.

Next: [03_MACHINE_LEARNING_FROM_BASICS.md](03_MACHINE_LEARNING_FROM_BASICS.md) — the ML core from
first principles.
