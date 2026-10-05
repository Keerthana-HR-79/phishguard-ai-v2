# 01 — Project Overview & Tech Stack (with full rationale)

---

## 1. What PhishGuard AI is

PhishGuard AI is a **real-time phishing-URL detection system**. Phishing is when an attacker
sends you a link that *looks* legitimate (`paypa1.com`, `secure-update-microsoft.xyz`,
`sbi.co.in.verify-account.ru`) to trick you into typing your password or card details on a
fake page. PhishGuard looks at a URL and answers one question: **is this link safe, suspicious,
or a phishing attempt?**

It gives three things back for every URL:
1. A **verdict**: `SAFE`, `SUSPICIOUS`, or `PHISHING`.
2. A **risk score** from 0 to 10.
3. The **reasons** — the exact signals that drove the verdict (e.g. "brand look-alike detected",
   "raw IP address in host", "on known-phishing blocklist").

### Why this problem is worth solving
- Phishing is the **#1 initial-access vector** in real-world breaches. It's the entry point for
  credential theft, ransomware, and business-email-compromise.
- A URL is available **before** the victim clicks — so URL-level detection is genuinely
  preventive, not just forensic.
- It's a problem where a small model + good engineering can produce a real, demonstrable tool —
  ideal for a portfolio/placement project that is *actually useful*, not a toy.

### The three surfaces (one backend brain)
| Surface | What the user does | Tech |
|---|---|---|
| **Web app** | Pastes a URL into the checker; views analytics on the dashboard | vanilla HTML/CSS/JS |
| **Chrome extension** | Installs it; every page they visit is checked automatically, with a warning banner + toolbar badge | Chrome Manifest V3 |
| **REST API** | (For both of the above, and any future client) `POST /predict_url` | FastAPI (Python) |

All three ultimately call the **same FastAPI backend**, which holds the trained model and the
detection rules. There is exactly **one source of truth for a verdict**.

---

## 2. Architecture at a glance

```
                         ┌─────────────────────────────────────────────┐
                         │              CLIENTS (any of 3)              │
                         │                                             │
   ┌──────────────┐      │  ┌───────────┐  ┌───────────┐  ┌─────────┐ │
   │  Web browser │──────┼─▶│ URL       │  │ Dashboard │  │ Chrome  │ │
   │  (a person)  │      │  │ Checker   │  │ (analytics│  │ MV3     │ │
   └──────────────┘      │  │ page      │  │  /stats)  │  │ extn.   │ │
                         │  └─────┬─────┘  └─────┬─────┘  └────┬────┘ │
                         └────────┼──────────────┼─────────────┼──────┘
                                  │ POST          │ GET         │ POST
                                  │ /predict_url  │ /stats      │ /predict_url
                                  ▼               ▼             ▼
                         ┌─────────────────────────────────────────────┐
                         │        FastAPI backend  (main.py)            │
                         │                                             │
                         │   _normalize_url()  (de-fang, cap, clean)    │
                         │            │                                 │
                         │            ▼                                 │
                         │   ┌─────────────────────────────────────┐   │
                         │   │  6-GATE SERVING LADDER               │   │
                         │   │  1  ML model score  ◀── predict_ml   │   │
                         │   │  2  structural-critical override     │   │
                         │   │  2b decisive blocklist               │   │
                         │   │  2c trusted-root allowlist → SAFE    │   │
                         │   │  3  confident-safe fast path         │   │
                         │   │  4  weighted heuristics + dampener   │   │
                         │   └─────────────────────────────────────┘   │
                         │            │                                 │
                         │            ├──▶ SQLite (log every event)     │
                         │            │                                 │
                         │            ▼                                 │
                         │   JSON: verdict, risk_score, reasons, meta   │
                         └─────────────────────────────────────────────┘
                                  │
                                  ▼  (offline, on demand)
                         ┌─────────────────────────────────────────────┐
                         │  export_to_bi.py → analytics/*.csv → Power BI│
                         └─────────────────────────────────────────────┘

   THE MODEL ARTIFACTS (loaded once at startup, live in backend/):
     model.pkl            calibrated XGBoost classifier
     char_vectorizer.pkl  character 3–5 gram TF-IDF
     word_vectorizer.pkl  word TF-IDF
     scaler.pkl           StandardScaler for the 22 numeric features
```

**The single most important architectural fact:** the **ML model runs first (Gate 1) on every
URL**, and the rules are a thin, principled layer *around* it — not the other way round. This is
covered exhaustively in [04_RULES_AND_DETECTION_LOGIC.md](04_RULES_AND_DETECTION_LOGIC.md).

---

## 3. The complete tech stack — and *why each, why not the alternatives*

This is the section interviewers probe hardest ("why did you choose X?"). For every choice
there's a real reason and a real rejected alternative.

### 3.1 Language: **Python 3.12.1**

**Why Python:** the entire mature machine-learning ecosystem (scikit-learn, XGBoost, numpy,
pandas) is Python-first. Using anything else would mean either reimplementing ML tooling or
calling Python over a bridge. The model *is* the project, so the project lives where the model
lives.

**Why 3.12.1 specifically:** it's pinned for **reproducible deployment**. Render (the host)
builds from `PYTHON_VERSION=3.12.1`; pinning avoids "works on my machine, breaks in the cloud"
from a newer Python changing a dependency's behavior. (This exact class of bug bit the sister
project, so it was pre-empted here.)

**Why not:**
- **JavaScript/Node for everything** — you'd lose scikit-learn/XGBoost. There's no equivalent
  calibrated-gradient-boosting + TF-IDF stack in JS that's production-trustworthy.
- **Java/Go** — great for services, poor for the ML training loop and data wrangling.

### 3.2 Backend framework: **FastAPI 0.111**

**What it is:** a modern Python web framework for building APIs.

**Why FastAPI:**
1. **Async-native.** A phishing check can involve slow I/O (optional live WHOIS/SSL lookups).
   FastAPI's `async def` + `asyncio.to_thread` lets the CPU-bound model inference and blocking
   lookups run **off the event loop**, so one slow request doesn't stall the server. (This is
   literally used in `main.py`: `await asyncio.to_thread(predict_ml, url)`.)
2. **Automatic validation** via **Pydantic** — request bodies are typed and validated for free;
   a malformed request gets a clean 422, not a 500.
3. **Automatic interactive docs** — `/docs` (Swagger UI) is generated from the code. Great for
   demoing the API live in an interview.
4. **Tiny, readable.** The whole API is a handful of decorated functions.

**Why not:**
- **Flask** — synchronous by default; you'd bolt on async and validation manually. FastAPI gives
  both out of the box. Flask was the obvious alternative and was rejected specifically for the
  async inference story and built-in Pydantic validation.
- **Django** — a full batteries-included web framework (ORM, admin, templating, auth). Massive
  overkill for a JSON API with one model and one table. Its ORM/admin/migrations would be dead
  weight; SQLite via the stdlib is enough here.
- **Node/Express** — would split the codebase across two languages (Python for ML, JS for the
  API) and require serializing the model across a boundary. One-language backend is simpler and
  faster to reason about.

### 3.3 ASGI server: **uvicorn**

**Why:** FastAPI is an ASGI app; it needs an ASGI server to actually run. uvicorn is the
standard, fast (uvloop/httptools under `[standard]`) choice. On Render the start command is
literally `uvicorn main:app --host 0.0.0.0 --port $PORT`.

### 3.4 The ML library: **XGBoost 2.0.3** (the heart of the project)

**What it is:** eXtreme Gradient Boosting — an ensemble of decision trees built one after
another, each correcting the previous ones' errors. (Explained from basics in
[03_MACHINE_LEARNING_FROM_BASICS.md](03_MACHINE_LEARNING_FROM_BASICS.md).)

**Why XGBoost — this is a top-3 interview question, so the full case:**

1. **It's the best-in-class algorithm for *tabular* data**, and 22 hand-built numeric features +
   sparse TF-IDF columns is exactly a tabular problem. On structured/tabular data, gradient-boosted
   trees consistently beat both linear models and deep nets.
2. **It captures non-linear interactions automatically.** Phishing signals combine
   non-linearly — "a hyphen in the domain" is nearly meaningless alone, but "hyphen **and** a brand
   look-alike **and** a suspicious TLD" is a strong signal. Trees split on exactly these
   conjunctions; a linear model cannot represent them without manual interaction terms.
3. **It handles mixed feature scales and sparse inputs** (a few dense numeric features next to
   thousands of sparse TF-IDF columns) gracefully.
4. **Built-in regularization** (`max_depth`, learning rate, tree count) controls overfitting —
   important given the leakage problems this project had to fight.
5. **Fast training and fast inference** — sub-millisecond per URL at serve time, so real-time
   checking (and background checking of every page in the extension) is feasible.
6. **Feature importance is inspectable** — you can see which signals matter, which mattered a lot
   for auditing and debugging the leakage.

**Why NOT the alternatives (know these cold):**
- **Logistic Regression** — linear; can't model the feature *interactions* that define phishing
  without hand-crafting every interaction term. It was used as a mental baseline; the honest
  stress tests showed trees materially outperform it on this feature set.
- **Random Forest** — also tree-based, but it builds trees **independently in parallel and
  averages** them (bagging). XGBoost builds trees **sequentially, each fixing the last one's
  residual errors** (boosting), which typically yields higher accuracy on the same data, plus a
  built-in learning-rate/regularization story. Random Forest is the closest competitor and a fair
  answer to "what else?" — XGBoost was chosen for the extra accuracy and control.
- **Deep learning (LSTM/CNN/Transformer on the URL string)** — rejected deliberately for four
  reasons: (a) it needs **far more data and compute** to beat boosted trees on tabular features;
  (b) it's a **black box** — for a security tool you want explainable "why", and XGBoost + the
  rule layer give clear reasons; (c) **inference cost** — a transformer per URL is heavy for a
  browser extension checking every page; (d) on **tabular** feature vectors, deep nets do **not**
  reliably beat gradient-boosted trees — this is a well-established result. A char-level neural net
  on the raw string is the "fancy" answer, and the honest engineering answer is that it wasn't
  worth the cost here.

### 3.5 Feature engineering & classical ML: **scikit-learn 1.4.2**

Used for the parts around XGBoost:
- **`TfidfVectorizer`** — turns the URL string into character n-gram (3–5) and word features.
  TF-IDF = Term Frequency × Inverse Document Frequency; it captures "which substrings/tokens
  appear and how distinctive they are". (Full explanation in doc 03.)
- **`StandardScaler`** — standardizes the 22 numeric features to mean 0 / std 1 so they're
  comparable.
- **`CalibratedClassifierCV`** (isotonic) — turns the raw XGBoost output into **honest
  probabilities** so a "0.6" really means "~60% likely phishing". Critical because the whole
  decision ladder uses probability thresholds.
- **`GroupShuffleSplit`** — the leakage-fix hero: splits train/test **by registrable domain** so
  the same domain can never appear in both. (This is what turned the fake 98% into an honest 74%.)

**Why scikit-learn:** it's the standard, well-tested toolkit for exactly these
preprocessing/calibration/splitting steps, and it interoperates cleanly with XGBoost.

### 3.6 Supporting numeric libs: **scipy 1.13, numpy 1.26**

- **scipy.sparse `hstack`** — the TF-IDF outputs are huge sparse matrices; scipy stacks them with
  the numeric features **without densifying** (which would blow up memory). The serving feature
  matrix is built as `hstack([char*0.05, word*0.05, numeric*15])`.
- **numpy** — array math underneath everything.

### 3.7 Fuzzy string matching: **rapidfuzz 3.9**

**Why:** to catch **typosquatting** — `paypa1.com`, `g00gle.com`, `arnazon.com`. rapidfuzz
computes a fast similarity ratio between a candidate domain piece and each known brand; a ratio
> 85 (after normalizing `0→o`, `1→l`, `3→e`) flags a brand look-alike. It's a C++-backed, much
faster drop-in for the older `fuzzywuzzy`.

**Why not** hand-rolled Levenshtein everywhere — rapidfuzz is faster and battle-tested; a naive
Python edit-distance per brand per URL would be too slow for the extension's per-page checks.
(A small hand-written `levenshtein` does exist for one specific rule check, but bulk fuzzy
matching uses rapidfuzz.)

### 3.8 Runtime enrichment (optional signals): **python-whois, requests**

- **python-whois** — looks up domain **age** at request time ("registered 3 days ago" is a mild
  phishing signal). It's slow and rate-limited, so it's optional, cached, time-limited (4s), and
  degrades gracefully to "unknown" — it never blocks a verdict.
- **requests** — legacy HTTP client; historically used for the live PhishTank feed, now largely
  superseded by the **local blocklist** snapshot (no network dependency in the hot path).

**Design principle here:** network calls are **enrichment, not gating**. The verdict is decided
by the model + local data; live lookups only add optional reasons. This keeps the system **fast,
deterministic, and offline-capable**.

### 3.9 Data storage: **SQLite** (Python stdlib `sqlite3`)

**What it stores:** every detection event — the URL (truncated), verdict, risk score, response
time, timestamp — in one table `phishing_events`. This powers the analytics dashboard and the
Power BI export.

**Why SQLite:**
1. **Zero-ops.** It's a single file, no server to run or secure. Perfect for a self-contained
   project and a free-tier host.
2. **In the standard library** — no dependency, no connection pooling, no credentials to leak.
3. **Plenty fast** for this write-light, read-light analytics workload.

**Why not:**
- **PostgreSQL / MySQL** — a networked DB server is overkill for a single-writer analytics log,
  adds ops burden, connection management, and (on Render) a paid add-on. It would be the right
  call only if this became multi-instance with heavy concurrent writes — which it isn't. The
  honest answer to "why not Postgres?" is *"I chose the simplest thing that fits the workload;
  Postgres would be the migration target if write concurrency or multi-instance scaling ever
  demanded it."*
- **A NoSQL store (Mongo)** — the data is perfectly relational/tabular (it becomes a star schema
  for Power BI), so a document store buys nothing.

**One honest caveat to mention:** SQLite on a single ephemeral Render instance means the event log
isn't durable across redeploys and wouldn't be shared across multiple instances — a known,
accepted limitation for a demo, and exactly why Postgres would be the scale-up path.

### 3.10 Analytics: **Power BI** (via `export_to_bi.py`)

**What it does:** `export_to_bi.py` reads the SQLite events and writes a **star-schema** set of
CSVs into `analytics/`:
- `fact_events.csv` — one row per detection (the fact table).
- `dim_date.csv`, `dim_type.csv`, `dim_result.csv` — dimension tables (date, scan type, verdict).
- `kpi_summary.csv` — pre-aggregated KPIs (total scans, detection rate, avg response time, …).

You import these into **Power BI Desktop** and wire the relationships
(`fact_events[date_key] → dim_date`, etc.) to build dashboards.

**Why a star schema:** it's the standard analytics data model — one central fact table
surrounded by dimension tables — which is exactly what Power BI's modeling and DAX measures are
designed for. Exporting a clean star schema is a resume-worthy "data engineering" touch.

**Security detail worth mentioning:** exported URLs are run through `csv_safe()`, which
neutralizes **CSV formula injection** (a URL starting with `=`, `+`, `-`, `@` could execute as a
formula when opened in Excel/Power BI) by prefixing a `'`. This is a real, often-overlooked
security control.

### 3.11 Frontend: **vanilla HTML + CSS + JavaScript** (no framework, no build)

Four pages: `index.html` (landing), `url-checker.html` (the checker), `dashboard.html`
(analytics), `extension.html` (install guide). JS in `js/` (`env.js`, `config.js`, `checker.js`,
`dashboard.js`), one stylesheet `css/styles.css`.

**Why vanilla:**
1. **Zero build step** — no webpack/vite, no `node_modules`, no transpile. The frontend is *just
   static files*, so Vercel serves them with **no build command at all** (`buildCommand: null`).
   Deployment is trivial and can't break in a build.
2. **The app is genuinely simple** — a form, a results card, a stats page. React/Vue would add a
   framework, a build toolchain, and hundreds of dependencies to render what is essentially one
   form and one table.
3. **Fast to load, easy to audit** — no framework runtime, small surface area, and the security
   review (XSS) is tractable.

**Why not React/Next.js:** they shine for large, stateful, component-heavy SPAs. This UI has
almost no client state. Choosing vanilla is the *senior* call here — "use the least tooling that
does the job" — and it's defensible in an interview precisely because you can articulate when you
*would* reach for React (a bigger, stateful dashboard product).

**Security detail:** every attacker-controlled string (the URL, each reason) is rendered with
`escapeHtml()` / `textContent`, never raw `innerHTML`, to prevent **DOM-based XSS** — because the
input to this app is, by definition, hostile URLs.

**Runtime config, no rebuild:** `js/env.js` sets `window.PHISHGUARD_API_BASE` (the backend URL).
`config.js` reads it first, then `localStorage`, then falls back to `http://localhost:8000`. This
is how the *same* static build points at localhost in dev and at the Render backend in
production — a one-line change, no rebuild.

### 3.12 Browser extension: **Chrome Manifest V3**

**Why MV3:** it's the **current, mandatory** extension platform (MV2 is being retired). MV3 uses
a **service worker** (not a persistent background page), which is more secure and resource-light,
and enforces a strict **Content Security Policy** (no `eval`, no `new Function`).

**Why an extension at all:** the checker page requires you to *paste* a URL. The extension makes
protection **passive and automatic** — it checks every page you navigate to and warns you *before*
you interact. That's the difference between a tool you remember to use and one that just protects
you. (Full detail in [05_CHROME_EXTENSION.md](05_CHROME_EXTENSION.md).)

### 3.13 Testing: **pytest 9.1.1**

**Why:** the whole point of the retrain history is *not regressing*. pytest gives a
**one-command, fully-offline** safety net (128 cases) that locks the behavioral contracts —
feature-vector length, the homograph set, the gate ordering, the trusted-root guard — so a future
edit can't silently reintroduce a fixed bug. Statistical model quality is measured separately by
the probe scripts (`fp_sweep.py`, `operating_point.py`, `cross_source_recall_probe.py`).
(Full detail in [06_TESTING.md](06_TESTING.md).)

### 3.14 Deployment: **GitHub (private) + Render (backend) + Vercel (frontend)**

- **GitHub (private repo)** — version control + the source both hosts deploy from.
- **Render** — runs the Python backend (free 512 MB tier). It installs `requirements.txt` and
  runs uvicorn. The trained `model.pkl` + vectorizers + `openphish.txt` blocklist are **committed**,
  so a fresh clone runs with **no training step**. Config lives in `render.yaml` (a "blueprint").
- **Vercel** — serves the static frontend (no build). Config in `vercel.json`.

**Why this split:** the backend needs a Python runtime + the model in memory (a real server —
Render); the frontend is static files best served from a CDN (Vercel). Each host does what it's
best at, both on free tiers.

**Why not one host for both:** you *could* serve the static files from FastAPI too, but splitting
gives the frontend a fast global CDN and keeps the backend focused. It also mirrors real-world
architecture (API tier + static/CDN tier).

**Honest deployment caveat to mention:** Render's free tier **sleeps after ~15 min idle**, so the
first request after a nap takes ~30–50 s (cold start). The frontend has a 10 s timeout and a
friendly retry message; for a live demo you warm it with a `/health` hit first.

---

## 4. Why the whole design is shaped the way it is (the through-line)

Three principles explain almost every choice above:

1. **The model is the product; everything serves the model.** Python (for the ML ecosystem),
   FastAPI (to serve it with async inference), scikit-learn/scipy/rapidfuzz (to feed it), pytest
   + probes (to protect it from regressions).

2. **Fast, deterministic, offline-first.** The verdict is decided by the in-memory model + local
   data (blocklist, allowlist), not by live network calls. Network lookups are optional
   enrichment with timeouts and graceful degradation. This is what makes per-page extension
   checking and cold-start-tolerant hosting viable.

3. **Least tooling that does the job.** Vanilla JS (no build), SQLite (no DB server), a private
   repo + two free hosts. Every "why not the heavier option?" has the same answer: it wasn't
   needed for this workload, and simplicity is a feature — but I can name the exact condition
   under which I'd upgrade each one (React for a big stateful UI, Postgres for concurrent
   multi-instance writes, a neural model given far more data + a non-lexical signal).

Next: [02_ARCHITECTURE_FILE_BY_FILE.md](02_ARCHITECTURE_FILE_BY_FILE.md) — every file, and the
exact path a request takes from the browser to the verdict and back.
