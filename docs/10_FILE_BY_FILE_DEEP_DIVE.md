# 10 — File-by-File Deep Dive (functions, logic, inputs/outputs, connections)

Doc [09](09_COMPLETE_FILE_REFERENCE.md) is the **breadth** map — one or two lines on *every* file so
you can name it. **This document is the depth map**: for each file that carries real logic it lists
the **actual functions, their inputs and outputs, the important logic inside them, and what imports
what**. If doc 09 tells you *that* `predict_ml_only.py` exists, this tells you *exactly what
`predict_ml()` does line-of-logic by line-of-logic*.

Read this when you want to be able to answer "walk me through that file" for any file in the repo.

---

## How the runtime files wire together (the import graph)

Everything at serving time hangs off one dependency chain. Knowing it makes every file below make
sense:

```
                          rules.json   (pure data: brands, keywords, TLDs, allowlist, weights)
                              │  loaded once at import
                              ▼
                          config.py    (parses rules.json → constants + helpers: stack_features,
                              │          parse_host, csv_safe, strip_www, ensure_scheme …)
              ┌───────────────┼───────────────────────────┐
              ▼               ▼                           ▼
        features.py     predict_ml_only.py            main.py
     (22-number vector) (loads 4 .pkl artifacts,   (FastAPI app: the 6-gate ladder,
              │           runs 3-tier predict_ml)   URL normalize, WHOIS/SSL, logging)
              │               │        ▲                  │        │
              └───────────────┘        │                  ▼        ▼
                    both feed the model │            database.py  url_augment.py
                                        └── main.py calls predict_ml()  (SQLite log)  (shared by
                                                                                       train + tests)
```

- **`rules.json` → `config.py`**: config reads the JSON once and exposes typed constants. Nothing
  else reads the JSON directly.
- **`config.py` → everything**: features, the model wrapper, the API, the probes and the training
  script all import their thresholds/weights/helpers from here, so there is a single source of truth.
- **`features.py` + `predict_ml_only.py`**: the model half. `features.py` turns a URL into 22
  numbers; `predict_ml_only.py` stacks those with the two TF-IDF blocks and runs the calibrated model.
- **`main.py`**: the orchestrator. It calls `predict_ml()` first, then wraps it in the rule gates,
  enriches with WHOIS/SSL, logs to `database.py`, and returns JSON.
- **`url_augment.py`**: not on the serving hot path — it is the shared "registrable domain / add
  path" toolkit used by **training** and the **tests**, kept in `backend/` so both import it.

---

# Part 1 — Backend runtime (the files a live request touches)

## `backend/config.py` — the single source of truth

**Purpose:** load `rules.json` and expose every tunable value and every shared string/URL helper, so
no threshold or parsing rule is ever hardcoded twice.

**Imports:** `json`, `os`, `re`, `functools`, `scipy.sparse` (lazily, inside `stack_features`).
**Imported by:** `features.py`, `predict_ml_only.py`, `main.py`, `train_ml_strong.py`, every probe.

**What it loads.** At import it opens `rules.json` **anchored on `__file__`** (so it loads no matter
what directory you launch from) and pulls out:

- `BRANDS`, `KEYWORDS`, `SUSPICIOUS_TLDS` — the lists baked into the model at train time.
- `TRUSTED_ROOTS` — the allowlist, lowercased into a `set` for O(1) `in` checks.
- `SHARED_HOSTING_ROOTS` — the subset of the allowlist that is "someone else's content" (github.io,
  blogspot.com …). An `assert not _orphan_shared` guards that **every** shared-hosting root is also a
  trusted root, so the two lists can never drift apart.

**Constants it exposes** (values live in `rules.json`, names live here):

| Group | Names |
|---|---|
| ML thresholds | `ML_SAFE_THRESHOLD = 0.35`, `ML_DECISION_THRESHOLD = 0.6` |
| Heuristic weights | `W_BRAND 3.0`, `W_TYPO 3.0`, `W_SUBDOMAIN 3.0`, `W_IP 2.5`, `W_PHISHTANK 4.0`, `W_NEW_DOMAIN 1.0`, `W_NO_SSL 0.5`, `W_KEYWORD 1.5` |
| Gate-4 knobs | `KEYWORD_MIN_PROB 0.55`, `DAMPENER_THRESHOLD 0.3`, `T_PHISHING 4.5`, `T_SUSPICIOUS 3.0` |
| Network / limits | `WHOIS_TIMEOUT_SEC 4`, `SSL_TIMEOUT_SEC 5`, `META_CACHE_TTL_SEC 900`, `MAX_URL_LEN 2048`, `NEW_DOMAIN_MAX_AGE_DAYS 30`, `RECENT_MAX_LIMIT 200` |
| Feature weighting | `FEATURE_WEIGHTS = (0.05, 0.05, 15)` |

**Functions:**

- **`stack_features(x_char, x_word, x_num)`** — the **one** place the feature blocks are combined.
  Lazily imports `scipy.sparse`, multiplies each block by its weight and horizontally stacks them into
  a single CSR sparse matrix: `hstack([x_char*0.05, x_word*0.05, x_num*15])`. Because *both*
  `train_ml_strong.py` and `predict_ml_only.py` call this exact function, the training-time matrix and
  the serving-time matrix are byte-identical in geometry and weight — they can never silently diverge
  (this was hardening fix **H3**).
- **`strip_www(host)`** — removes a leading `www.` **as a true prefix** (`host[4:]` only when it
  starts with `www.`), *not* a character-class `lstrip` — so `www.whatsapp.com` → `whatsapp.com` and
  never `hatsapp.com`. A locked test guards this.
- **`ensure_scheme(url)`** — prepends `http://` unless the string already starts with a real scheme,
  matched by the regex `^[a-zA-Z][a-zA-Z0-9+.\-]*://` (not a naive `"://" in url`).
- **`parse_host(url)`** — returns the lowercased host via `urlsplit`, stripping `user@` credentials
  and `:port`. This is the security-correct host extraction that closed the "localhost-in-the-path"
  bypass — checks key on the *parsed host*, never on a substring of the whole URL.
- **`host_is_ip(host)`** / **`host_is_loopback(host)`** — typed checks via `ipaddress`; loopback
  covers `127.0.0.0/8`, `::1`, and the literal `localhost`.
- **`csv_safe(value)`** — the CSV-formula-injection guard: if a value starts with `= + - @` or a
  tab/CR, it is prefixed with a single quote so spreadsheet software can't execute it as a formula.
  Used by the FP-report writer and the Power BI export.

---

## `backend/features.py` — URL → 22 numbers

**Purpose:** `extract_features(url)` turns a raw URL string into **exactly 22 numeric features** —
the hand-engineered numeric block of the model input. This is the single source of truth for those
numbers, used identically at train and serve time.

**Imports:** `re`, `math`, `unicodedata`, `rapidfuzz.fuzz`, and `BRANDS/KEYWORDS/SUSPICIOUS_TLDS`
from `config`. **Imported by:** `predict_ml_only.py`, `train_ml_strong.py`, and every probe that
scores the model.

**Helper functions:**

- **`entropy(s)`** — Shannon entropy of the string's character distribution; high entropy flags
  random-looking hostnames (`g7x2k9qz.com`).
- **`clean_text(url)`** — lowercases and strips the scheme so tokenisation is consistent.
- **`_decode_idn(host)`** — decodes punycode (`xn--…`) labels back to Unicode so a homograph attack
  is visible to the confusable check.
- **`_skeleton(s)`** — NFKD-normalises and folds confusable characters to ASCII via `_CONFUSABLES`
  (a Cyrillic/Greek→Latin lookalike map), producing a "skeleton" so a Cyrillic `аpple` collapses to
  `apple` and is caught as a brand spoof.

**The 22 features (index → meaning):** exact order matters — a locked test asserts length 22 and the
meaning of the security indices.

| # | Feature | # | Feature |
|---|---|---|---|
| 0 | URL length / 100 | 11 | `@` present in the **authority** (credential trick) |
| 1 | number of `.` | 12 | `@` combined with a dot (stronger credential signal) |
| 2 | number of `-` | 13 | path-segment count |
| 3 | number of `/` | 14 | hyphen in the registrable domain |
| 4 | digit count | 15 | subdomain depth |
| 5 | Shannon entropy | 16 | suspicious TLD (from the `rules.json` list) |
| 6 | keyword count in URL | 17 | host is localhost / `127.0.0.1` |
| 7 | max brand similarity / 100 | 18 | keyword tokens **in the host** |
| 8 | brand-spoof flag | 19 | hyphens in the host |
| 9 | brand-spoof **and** keyword | 20 | `xn--` punycode present |
| 10 | host is a raw IP (regex) | 21 | non-ASCII character in the host |

Feature **7/8** use `rapidfuzz.fuzz.ratio` with a threshold `>85` against each known brand — this is
the fuzzy typosquat detector (`paypa1`, `g00gle`, `arnazon`). Feature **9** ("brand look-alike *and*
a phishing keyword") is the high-precision corroboration index the model and the structural gate both
lean on.

**Robustness contract:** the whole function is wrapped so that *any* parsing exception returns
`[0]*22` — a malformed URL yields an all-zero vector instead of crashing the request. A test asserts
this.

---

## `backend/predict_ml_only.py` — the model half (`predict_ml`)

**Purpose:** load the four trained artifacts **once** at import and expose
`predict_ml(url) → (pred, prob, override_reason)` — the pure model verdict plus the three
short-circuit tiers that must run *inside* the model wrapper (not as heuristics).

**Imports:** `pickle`, `re`, `os`, `features.extract_features`, and from `config`:
`stack_features`, `ML_DECISION_THRESHOLD`, `TRUSTED_ROOTS`, `parse_host`, `host_is_ip`,
`host_is_loopback`. **Imported by:** `main.py` (Gate 1) and the model probes.

**Artifact loading.** `_load_pkl(name)` opens each `.pkl` **anchored on `_MODEL_DIR` (`__file__`'s
folder)**, so the model loads regardless of the launch directory. Four globals are populated at
import: `model` (calibrated XGBoost), `char_vectorizer`, `word_vectorizer`, `scaler`.

**Helper:** `_extract_root_domain(host)` uses `_TWO_PART_TLDS` (`co.uk`, `co.in`, `ac.in`, …) to
return the registrable root — so `foo.icici.co.in` → `icici.co.in` and the allowlist check is exact.

**`predict_ml(url)` — the three tiers (in order):**

1. **Tier 0 — allowlist / loopback short-circuit (return SAFE early):**
   - `host_is_loopback(host)` → `return (0, 0.001, "Localhost dev environment")`.
   - registrable root in `TRUSTED_ROOTS` → `return (0, 0.001, "Globally trusted domain")`.
   This is what protects real brands (`google.com`, `byjus.com`) from ever being scored — an exact
   root match only, so `dropbox.com.evil.xyz` is **not** protected and falls through to the model.

2. **Tier 1 — structural-critical override (return PHISHING early):**
   ```python
   brand_spoof_corroborated = feats[8] and (feats[9] or feats[16] or feats[20] or feats[21])
   if host_is_ip(host) or feats[11] or brand_spoof_corroborated:
       return (1, 0.999, "Critical: Structural security risk detected")
   ```
   A raw-IP host, an `@`-credential authority, or a brand look-alike *corroborated* by a second
   signal (keyword, suspicious TLD, punycode, or non-ASCII host) is treated as certain — these are
   things a URL string can prove, so they don't wait on the probabilistic model.

3. **Tier 2 — the calibrated model:** strip the scheme (`text_url = re.sub(r"^https?://", "", url)`
   so the model can't cheat on `http` vs `https`), build the char/word TF-IDF, extract the 22
   numbers, `stack_features(...)`, then `prob = model.predict_proba(X)[:,1]` and
   `pred = int(prob > ML_DECISION_THRESHOLD)` (0.6). Returns `(pred, prob, None)`.

---

## `backend/main.py` — the FastAPI app and the 6-gate ladder

**Purpose:** the HTTP surface (**v3.2.0**). Validates input, normalises the URL, runs the **6-gate
detection ladder** (model first, rules as a wrapper), optionally enriches with WHOIS/SSL, logs the
event, and returns the verdict JSON. This is the file a request actually hits.

**Imports:** `fastapi`, `pydantic`, `os`, `time`, `asyncio`, `contextlib`, `socket`, `ssl`,
`requests`, `whois`, plus `predict_ml`, all of `config`, and `database`. **Imported by:** nothing —
it's the entrypoint (`uvicorn main:app`).

**Endpoints:**

| Method + path | What it does |
|---|---|
| `POST /predict_url` | The main endpoint — runs the 6 gates, returns `{result, risk_score, reasons, ml_probability, domain, meta}`. |
| `POST /report_false_positive` | Appends a user-reported false positive to the FP-log CSV (each field run through `csv_safe`). Feeds `build_legit_dataset.py`. |
| `GET /stats` | KPI aggregate for the dashboard (delegates to `database.get_stats()`). |
| `GET /recent?limit=` | Recent events (clamped to `RECENT_MAX_LIMIT`). |
| `GET /health` | Liveness check (Render's health path). |
| `GET /` | Basic service banner. |

**URL hygiene — `_normalize_url(raw)`** runs before anything else and de-fangs hostile input:
- `hxxp`→`http`, `[.]`/`[dot]`→`.`, strips `[`/`]` defang brackets (but **preserves** a real
  `[IPv6]` authority),
- collapses redundant slashes with `(?<!:)/{2,}` → `/` (so `byjus.com//////login` → `…/login`) while
  keeping the `://` after the scheme,
- caps length at `MAX_URL_LEN` (2048).

**The 6 gates (literally the body of `predict_url_endpoint`):**

1. **Gate 1 — ML first.** Call `pred, prob, override_reason = predict_ml(url)`. **The model runs
   before any rule.**
2. **Gate 2 — structural-critical override → PHISHING (score 10).** If `predict_ml` returned the
   `"Critical: Structural security risk detected"` reason (raw-IP / `@` / corroborated spoof), it's a
   hard block.
3. **Gate 2b — decisive blocklist → PHISHING (score 9).** `check_blocklist(url)` hit on the local
   OpenPhish/PhishTank frozenset. Carve-out: a blocklist hit under a **shared-hosting root** overrides
   the allowlist (a legit page there is never on the blocklist), but a blocklist hit on a **real-brand
   root is ignored** so a stale feed entry can never flip `google.com`.
4. **Gate 2c — trusted-root allowlist → SAFE.** `override_reason == "Globally trusted domain"` and
   the host is *not* an abused shared-hosting tenant → SAFE. `_shared_host_allowlisted` is the exact
   guard: `(override_reason == "Globally trusted domain" and is_shared_hosting_host(domain))`.
5. **Gate 3 — confident-safe fast path.** If the model is confidently below `ML_SAFE_THRESHOLD`
   (0.35) and no structural flag fired, return SAFE without running the heuristic scorer.
6. **Gate 4 — weighted heuristics + dampener.** The graded middle. Starts from `score = prob*3`, then
   adds weighted flags (`W_BRAND`, `W_TYPO`, `W_SUBDOMAIN`, `W_IP`, `W_NEW_DOMAIN`, `W_NO_SSL`,
   `W_KEYWORD` — the keyword weight only counts when `prob >= KEYWORD_MIN_PROB` 0.55). Then the
   **confidence dampener**: `if prob < DAMPENER_THRESHOLD (0.3): score *= 0.5` — if the model is
   confident the URL is fine, heuristic noise can't push it over the line. Finally: `score > T_PHISHING
   (4.5)` → PHISHING, `>= T_SUSPICIOUS (3.0)` → SUSPICIOUS, else SAFE.

**Enrichment helpers (optional, cached, non-blocking):**
- `get_domain_age()` (python-whois) and `check_ssl()` (a `socket`+`ssl` handshake) are wrapped as
  `_age_async` / `_ssl_async` via `asyncio.to_thread`, each behind a TTL cache
  (`META_CACHE_TTL_SEC` 900s), so a slow WHOIS server never blocks the event loop and repeat lookups
  are instant. Their results are advisory `meta` fields, not gate-deciders on their own.
- `check_blocklist()` matches exact URL and trailing-slash form against `_PHISH_BLOCKLIST`, a
  `frozenset` built once by `_load_local_blocklist()` from `openphish.txt` + `phishtank.csv`.
- Host helpers `extract_domain` (= `parse_host`), `levenshtein`, `check_typo`, `check_subdomain`,
  `is_legit_brand_domain`, `is_shared_hosting_host`.

**Config from environment:** `CORS_ORIGINS` (comma-separated; `*` in dev, locked to the Vercel URL in
prod), `PHISHGUARD_DB`, and the FP-log path all read from env so nothing is hardcoded for deploy.

---

## `backend/database.py` — the SQLite event log

**Purpose:** persist every verdict and answer the dashboard's KPI queries. One table,
`phishing_events (id, type, content, result, risk_score, response_time, timestamp)`.

**Imports:** `sqlite3`, `datetime`, `os`, `contextlib.closing`. **Imported by:** `main.py`,
`export_to_bi.py`.

- **`init_db()`** — creates the table and two indexes (`idx_timestamp`, `idx_result`) if absent.
  **Runs automatically on import** (`init_db()` at the bottom), so a fresh clone has a working DB with
  no setup step.
- **`log_event(type_, content, result, risk_score, response_time)`** — one parameterised `INSERT`
  (no string formatting → no SQL injection); caps `content` at 500 chars and stores a UTC ISO
  timestamp.
- **`get_stats()`** — one aggregate query for totals (phishing/suspicious/safe/url counts, avg
  response), one grouped query for the **7-day daily breakdown**, one for the **top-10 most-flagged
  URLs**. Guards division-by-zero (`total or 1`). Returns the exact dict the dashboard renders.
- **`get_recent_events(limit)`** — most recent N events, newest first. Defensively coerces `limit` to
  a non-negative int **at the data layer too** — because a negative `LIMIT` means "no limit" in SQLite
  and would dump the whole table.

Every connection goes through `with closing(_get_conn())` so handles are always released (hardening
fix P2), and `row_factory = sqlite3.Row` gives dict-like rows.

**Swap-to-Postgres note:** the module header documents that changing `DB_PATH` to a `postgres://` URL
is the intended production upgrade path.

---

## `backend/url_augment.py` — the leakage-fix toolkit (shared by train + tests)

**Purpose:** the helpers that **break the "URL has a path ⇒ phishing" artifact** and enable the
**leakage-free grouped split**. Not on the serving path — it's imported by `train_ml_strong.py`,
`build_legit_dataset.py`, `generate_adversarial.py`, and the tests.

**Imports:** `random`, `urllib.parse.urlparse`.

**Data:**
- `PATH_POOL` — ~60 realistic paths, deliberately mixing ordinary browsing paths (`/about`,
  `/products/item/1042`) **and** security-flavoured ones (`/login`, `/verify-email`,
  `/reset-password`, `/wp-admin`). Security paths are legitimate on a legit host, so including them on
  legit domains teaches the model that the **path is not the phishing signal — the host is**.
- `DEEP_SEGMENTS` — tokens used to build deep, keyword-stacked paths
  (`/login/verify/account/secure/…`).

**Functions:**
- **`registrable_domain(url)`** — best-effort registrable domain, honouring `_TWO_PART_TLDS`
  (`a.b.co.uk` → `b.co.uk`) and stripping `www`/`@`/port. **This is the grouping key** for
  `GroupShuffleSplit`, so it directly implements the anti-leakage split.
- **`has_path(url)`** — true if the URL carries a path or query. Used to assert the ~50/50 pathed
  balance after augmentation.
- **`strip_to_host(url)`** — reduces a URL to `scheme://host` (the "bare" variant).
- **`add_path(url, rng)`** — appends a realistic path; **~35% of the time** builds a deep 2–7 segment
  keyword-stacked path from `DEEP_SEGMENTS`, otherwise draws one from `PATH_POOL`. Applied to **both**
  classes at train time, so path shape/depth/keyword-stacking carry no class signal. The 0.15→0.35
  rate bump (v3.4) fixed a real regression where deep paths tipped non-allowlisted legit hosts (e.g.
  `vedantu.com`) over the line — documented right in the docstring.
- `_prep`, `_host_of` — internal normalisers that drop defang brackets before parsing (matching
  `features.py`).

---

## `backend/rules.json` — all detection data as pure JSON

**Purpose:** the **single data file** that lets you tune the detector without touching Python.
Loaded only by `config.py`.

Five sections:
- **`brands`** (32) — spoof targets (global tech/finance + Indian: `flipkart`, `phonepe`, `paytm`,
  `icici`, `irctc`). **Baked into the model** → changing them needs a retrain.
- **`keywords`** (41) — phishing vocabulary (`login`, `verify`, `suspend`, `giftcard`, `invoice`…).
  Also baked in.
- **`suspicious_tlds`** (19) — cheap/abused TLDs (`xyz`, `tk`, `zip`, `click`…). Baked in.
- **`trusted_roots`** (allowlist, ~240 entries) — **NOT baked in**; a pure false-positive guard.
  Curated global top sites + Indian banking/gov/payments/e-commerce + commonly-abused-but-legit hosts
  (dropbox, arxiv). **Exact registrable-root match only**, so `dropbox.com.evil.xyz` is still judged
  by the model. Edit freely, no retrain.
- **`shared_hosting_roots`** (7: github.io, blogspot.com, wordpress.com, readthedocs.io, workers.dev,
  ghost.io, tumblr.com) — the subset where trust belongs to the *platform*, not the tenant. Enables
  the Gate-2b carve-out. The header comment explains why big CDN/shortener commons
  (`amazonaws.com`, `bit.ly`) are deliberately *excluded* from this list.
- **`scoring`**, **`network`**, **`limits`** — every threshold and weight listed in `config.py` above.

The top-of-file `_comment` documents the bake-in-vs-live distinction so nobody edits a brand and
forgets to retrain.

---

# Part 2 — The training pipeline (builds the four `.pkl` artifacts)

## `backend/train_ml_strong.py` — the model factory (v3.1+, ships v3.5)

**Purpose:** the one script that produces `model.pkl` + the three transformers. Its whole design is
about **honesty**: kill leakage, decorrelate the path artifact, and be deterministic.

**Imports:** `numpy`, `pandas`, `pickle`, `random`, `re`; from sklearn `GroupShuffleSplit`,
`TfidfVectorizer`, `StandardScaler`, `CalibratedClassifierCV`, `classification_report`; `XGBClassifier`;
and the project's own `extract_features`, `url_augment` helpers, `TRUSTED_ROOTS`, `stack_features`.

**The pipeline, in order:**

1. **Load & combine** `final_dataset.csv` + `adversarial_phishing.csv` (2× boost) + `legit_urls.csv`
   + optional `fresh_phishing.csv` (novel active bare domains). `MAX_PER_CLASS = 150_000` before
   augmentation.
2. **Label-noise cleaning (A5):** compute `registrable_domain` per row, then
   **(a)** drop any phishing row whose root is in `TRUSTED_ROOTS` (a feed mislabelling `byjus.com`
   can't poison training); **(b)** drop shortener/free-host roots (`bit.ly`, `github.io`, …) from
   **both** classes because one root there spans thousands of unrelated sites. Rule **(c)** — dropping
   every phishing row whose root merely appears in the legit set — was tried and **reverted** because
   it *raised* FP from 10.4%→13.8%; the code comment preserves that experiment.
3. **Balance** to `min(phishing, legit, cap)` per class.
4. **Path-decorrelation augmentation (the core fix):** emit each URL **twice** — once bare, once
   pathed via `add_path` — for both classes, so ~50% of each class is pathed from an identical path
   distribution. A sanity print asserts the ~50% pathed balance per class.
5. **Grouped 3-way split by registrable domain (leakage-free):** split **row indices** with
   `GroupShuffleSplit` into train / calibrate / test so **no domain appears in two splits**. Three
   `assert …isdisjoint(…)` lines make leakage a hard failure, not a silent bug.
6. **Fit transforms on TRAIN ONLY (M10):** `char_vec` (char 3–5 grams, 3000 dims), `word_vec` (1000
   dims) and the `StandardScaler` are `.fit()` on the train slice, then `.transform()` the calibrate
   and test slices — so the reported score never saw its own preprocessing. `_build(slice)` applies
   the transforms and the exact serving weights via `stack_features`.
7. **Train** `XGBClassifier(n_estimators=400, max_depth=7, learning_rate=0.05, random_state=42,
   n_jobs=1)` — `n_jobs=1` + fixed seed make the model **bit-reproducible** (M11), which is what makes
   the golden-score tests meaningful.
8. **Calibrate** with `CalibratedClassifierCV(base, cv="prefit", method="isotonic")` fit on the
   **disjoint** calibration slice (fixes the old leaky calibration).
9. **Report** the honest grouped `classification_report` + confusion matrix (the ~74% number), and
   **save** the four `.pkl` files.

The header docstring is itself a mini changelog (A1/A2/C1/C2/M10/M11) — a good file to quote in an
interview about leakage.

## The data-building scripts

- **`build_dataset.py`** — assembles `data/processed/final_dataset.csv` (the ~1.5M-row `url,type`
  table) from the raw phishing feeds (OpenPhish/PhishTank/Phishing.Database-ACTIVE) and legit sources.
  The raw-feeds → one-labelled-table step.
- **`build_legit_dataset.py`** — builds `legit_urls.csv` (the negative class **and** the 80k FP-sweep
  set) from three no-signup public sources: **Tranco Top-1M** (always take the top 30k by rank — real
  people visit those, skipping them caused FPs on dropbox/wordpress — plus a sampled long tail to 80k),
  an embedded **curated Indian/SaaS seed list** (~150 URLs, up-weighted ~10× via *distinct* variants
  from `expand_variants` so the emphasis survives dedup — the old `*10` produced identical strings that
  `dict.fromkeys` silently collapsed, bug A6), and **`pending_retrain.csv`** (real FP reports from the
  extension). Each domain contributes **both** a bare host and a varied pathed URL via `add_path`, so
  legit examples aren't overwhelmingly path-free (root cause of the path artifact, A1/A2).
- **`generate_adversarial.py`** — synthesises `adversarial_phishing.csv` (~12k). Its vocabulary is
  **deliberately wider** than `features.py`'s lists (adds `refund`, `giftcard`, banks, crypto,
  logistics brands) so the model must learn phishing *wording* from data, not memorise the 25 feature
  tokens (A3). `obfuscate()` does leetspeak (`o`→`0`, `l`→`1`); `brand_variations()` builds
  `paypal.com.secure-login.xyz`-style hosts; `keyword_salad()` builds pure-keyword hosts
  (`verify-account-now.net`). ~50% get a path so path-presence isn't a tell.
- **`harvest_fresh_data.py`** — stages currently-active phishing domains as `fresh_phishing.csv`
  (novel bare registrable roots — the real recall gap) and reserves a **disjoint** `fresh_holdout.csv`
  the model never trains on (the honest recall probe set).
- **`refresh_feeds.py`** — refreshes the local blocklist from the **live OpenPhish feed** (the shipped
  `openphish.txt` is a snapshot; this pulls current live phishing).

---

# Part 3 — Measurement probes (produce the numbers; never served)

All probes import `extract_features` + `stack_features`, so they score the model with the **exact
serving weights**. Full context in [06_TESTING.md](06_TESTING.md).

**`fp_sweep.py` (the gated metric) — read in depth:** loads the four artifacts from a directory
(`.` = live model, or a backup dir passed as `argv[1]` so two versions score the *same* URL set),
sweeps **all ~80k** `legit_urls.csv` URLs through the **model alone** (allowlist + structural rules
bypassed), batches the vectorizers for speed, computes `probs = predict_proba[:,1]`, and reports the
false-positive rate `= (probs > 0.6).mean()` plus the **worst-15 highest-probability legit URLs** so
the failure mode is visible. **This is the hard gate: ≤ 9.70% to ship; v3.5 = 6.23%.**

| Probe | What it measures | v3.5 headline |
|---|---|---|
| `operating_point.py` | **Recall at equal FP** — the fair cross-version comparison (same FP budget, not same threshold) | 61.3% at the 9.70% gate |
| `cross_source_recall_probe.py` | Recall on an OpenPhish feed of **novel roots**, blocklist/allowlist bypassed | 70.4% (honest generalisation) |
| `fresh_recall_probe.py` | Recall on the 5k unseen same-feed holdout | 55.6% @ 0.60 |
| `homograph_probe.py` | The canonical **14-case** IDN/punycode + typosquat set; also the source `test_model_invariants.py` imports so probe and test can't diverge | 14/14 |
| `parent_path_probe.py` | Parent-vs-path flips on **non-allowlisted** legit hosts (measures the model, not the allowlist) | 0/9 (was 5/9) |
| `byjus_pathfix_probe.py` | The byjus deep-path artifact at the model level | all SAFE (worst 0.524 < 0.6) |
| `path_artifact_probe.py` | Identical domains **bare vs pathed** — proves the model no longer keys on "has a path" | no flips |
| `model_stress_test.py` | Curated realistic mix, model-only | ~74–75% |
| `keyword_rule_probe.py` | Sweeps the keyword operating point — how `KEYWORD_MIN_PROB = 0.55` was chosen | picked 0.55 |
| `probe_model.py` | What the raw model does on non-allowlisted legit companies (pure model behaviour) | diagnostic |
| `b4_signal_probe.py` | Empirical test of whether **domain-age is a leakage artifact** of the stale snapshot — why WHOIS age was *not* folded into the model | rejected the feature |
| `inspect_data.py` | Reports training-data composition; locates the path artifact | diagnostic |
| `explain_decision.py` | For any URL, prints **which tier decided** (allowlist / structural / model) + the raw prob | diagnostic |
| `test_ml_only.py` | Standalone labelled sanity check (model-only). **Not** part of the pytest suite | manual check |

> The distinction to state out loud: the **pytest suite** locks behaviour (can't regress a fixed
> bug); the **probes** own the quality numbers. A retrain must clear `fp_sweep.py` ≤ 9.70% or it's
> reverted.

---

# Part 4 — Analytics bridge

## `backend/export_to_bi.py` — SQLite → Power BI star schema

**Purpose:** turn the operational `phishing_events` log into a Power BI-ready **star schema** (one
fact table + dimensions). Run manually; writes into `analytics/`.

**Imports:** `sqlite3`, `csv`, `datetime`, and **`csv_safe` from `config`** — every exported URL
passes through it so a URL like `=cmd|...` can't execute as a spreadsheet formula.

**Functions (one CSV each):**
- **`export_fact_events()`** — one row per detection event, with derived `date_key` and `hour`
  columns for time-slicing; content truncated to 200 chars and `csv_safe`-guarded.
- **`export_dim_date()`** — a date dimension (year, month, month-name, day, weekday, ISO week) for
  every distinct event date.
- **`export_dim_type()`** / **`export_dim_result()`** — small static dimensions; `dim_result` carries
  severity + display hex colours (`#E24B4A` etc.) and a sort order so Power BI visuals colour
  consistently.
- **`export_kpi_summary()`** — pre-aggregated KPIs (totals, detection rate, avg response ms, avg risk,
  threats-this-week) so a dashboard needs no DAX to show headline numbers.
- **`main()`** — creates `analytics/`, warns and exits gracefully if the DB doesn't exist yet, runs
  all five exports, and prints the exact Power BI relationship wiring
  (`fact_events[date_key] → dim_date[date_key]`, etc.).

---

# Part 5 — The live web app (`frontend/`, vanilla JS)

Load order on each page: **`env.js` → `config.js` → the page script**. No build step.

- **`js/env.js`** — the **one deploy knob**. Sets `window.PHISHGUARD_API_BASE`. Currently
  `"https://phishguard-backend-ihvp.onrender.com"` (the live Render backend). Empty = local-dev
  fallback. Loaded *before* `config.js` so one edit repoints the whole frontend.
- **`js/config.js`** — resolves `API_BASE` in priority order **`window.PHISHGUARD_API_BASE` →
  `localStorage["phishguard_api_base"]` → `http://localhost:8000`** (trailing slashes stripped), so
  deploying needs no code edit. Also defines **`fetchWithTimeout(url, opts, ms=10000)`** — a `fetch`
  wrapped in an `AbortController` that aborts after the timeout so the UI never hangs on a dead
  backend. Both are shared by every page.
- **`js/checker.js`** — the URL-checker page. `check()` reads the input, `POST`s `{url}` to
  `/predict_url` via `fetchWithTimeout`, and renders a verdict card (`renderResultCard`) with the
  colour/icon/label for PHISHING/SUSPICIOUS/SAFE, a risk bar (`score/10`), the reason list, and a meta
  block (domain, ML probability, domain age, SSL). **Every interpolated value goes through
  `escapeHtml()`** (the `&<>"'` replacer) so a hostile URL or reason string can't inject markup.
  Wires four example URLs and Enter-to-check on `DOMContentLoaded`. Shows a clear timeout/offline
  error pointing at `API_BASE`.
- **`js/dashboard.js`** — the analytics page. `load()` fetches `/stats` and `/recent?limit=15` **in
  parallel** (`Promise.all`), then renders: **KPI cards** (`renderKPIs`), a **7-day bar chart**
  (`renderChart`, pure CSS-height bars — total vs phishing), a **recent-scans table**
  (`renderRecent`, time/type/content/result/score), and a **top-threats table** (`renderTopThreats`).
  All cell values `escapeHtml`-escaped. A **Refresh** button re-runs `load()`; an export hint points
  at `export_to_bi.py`. Handles the empty state ("No scans yet…") and the API-down state gracefully.
- **HTML pages** — `index.html` (landing), `url-checker.html` (primary UX), `dashboard.html`
  (analytics), `extension.html` (install guide). `css/styles.css` styles all of them.
  `phishguard-extension.zip` is the packaged extension offered for download.

---

# Part 6 — The Chrome extension (`extension/`, Manifest V3)

- **`manifest.json`** — MV3 declaration. `manifest_version: 3`, minimal permissions **`scripting` +
  `storage`** (no broad `tabs` permission needed — navigation is read from the update event),
  `host_permissions: ["<all_urls>"]`, a background **service worker** (`background.js`), and a toolbar
  **popup** (`popup.html`) with three icon sizes.
- **`config.js`** — shared by **both** the popup (`<script src>`) and the service worker
  (`importScripts`), so they use one API base, one timeout helper and one cache. `getApiBase()` /
  `getDashboardUrl()` read a `chrome.storage.local` override first (deploy needs no code edit), else
  the local-dev defaults. `fetchWithTimeout` (8s abort). A **bounded, TTL'd cache**: `cacheGet`
  (60s freshness), `cacheSet`, and **`evictCache()`** which trims to `CACHE_MAX_ENTRIES = 200`
  oldest-first — and only touches keys under the `cache:` prefix so config keys survive (bug L8).
- **`background.js`** — the always-on service worker. On `chrome.tabs.onUpdated` with
  `status === "complete"`, it `shouldSkip()`s chrome-internal/extension/file/data URLs, calls
  `checkUrl()` (cache → `/predict_url`, fail-silent on timeout), paints the toolbar **badge**
  (`⛔/⚠/✓` by result), and for **PHISHING** injects a warning banner. The banner is built by
  **`renderBanner()`**, a self-contained function shipped to the page via
  `chrome.scripting.executeScript({func, args})` and assembled **entirely with `createElement` +
  `textContent`** — no `innerHTML`, no `new Function`. This is the fix for **two security bugs** (H2):
  the old `new Function(code)` was blocked by the MV3 service-worker CSP (banner never showed), and
  `innerHTML` was a DOM-XSS sink for attacker-controlled reason strings.
- **`popup.js`** — the toolbar popup. `init()` reads the active tab's URL (skipping `chrome://`),
  shows it via `textContent` (never `innerHTML` — the URL is attacker-controlled), and calls
  `checkUrl()`. `renderResult()` builds a **static** scaffold once, then fills icon/label/score via
  `textContent` and the reason `<li>`s via `createElement`+`textContent`. A **Re-check** button and a
  configurable **Open Dashboard** link round it out; `setBadge()` mirrors the background badge.
- **`popup.html`** — the 320px popup markup + inline CSS (header, URL strip, result area, risk bar,
  reasons list, spinner, footer). Loads `config.js` **then** `popup.js`.

---

# Part 7 — Tests (locked contracts)

Fully enumerated in [06_TESTING.md](06_TESTING.md): **62 functions → 128 parametrized cases** across
10 files + `conftest.py`. Each case pins a contract tied to a real past bug — the feature vector is
always length 22, an email in a *query* never fires the `@`-authority rule, a stale blocklist entry
can never flip `google.com`, `strip_www` is a true-prefix strip, the 14/14 homograph set holds, the
gate **ordering** is correct. They touch no model artifact and make no network call, so they can't
regress the FP gate — they lock behaviour *around* the model while the probes own the model's numbers.

---

## One-paragraph recap

A request enters **`main.py`**, is de-fanged by `_normalize_url`, and hits the **6-gate ladder**. Gate
1 calls **`predict_ml`** in **`predict_ml_only.py`**, which short-circuits on the **allowlist**
(`rules.json` via **`config.py`**) and on **structural certainties** (`features.py`'s 22 numbers),
otherwise runs the **calibrated XGBoost** built by **`train_ml_strong.py`** on data assembled by the
`build_*`/`harvest`/`generate` scripts and measured by the probes (gated by **`fp_sweep.py`**). The
verdict is logged by **`database.py`**, exported for Power BI by **`export_to_bi.py`**, and shown to
the user by the **vanilla-JS frontend** and the **MV3 extension** — both talking to the same
`/predict_url`, both rendering with `textContent`/`escapeHtml` so a hostile URL can never inject
markup. **There is no file in this project you can't now explain at the function level.**

---

*Full set:* [README](README.md) · [01](01_OVERVIEW_AND_TECH_STACK.md) ·
[02](02_ARCHITECTURE_FILE_BY_FILE.md) · [03](03_MACHINE_LEARNING_FROM_BASICS.md) ·
[04](04_RULES_AND_DETECTION_LOGIC.md) · [05](05_CHROME_EXTENSION.md) · [06](06_TESTING.md) ·
[07](07_INTERVIEW_QA.md) · [08](08_RESUME_POINTS.md) · [09](09_COMPLETE_FILE_REFERENCE.md) ·
**10 File-by-File Deep Dive**
