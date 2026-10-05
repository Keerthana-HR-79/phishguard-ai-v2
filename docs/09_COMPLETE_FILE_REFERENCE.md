# 09 — Complete File Reference (every file in the project)

Doc [02](02_ARCHITECTURE_FILE_BY_FILE.md) explains the **core runtime files and the request
lifecycle** in depth. This document is the **exhaustive index** — *every* file and folder in the
repository, including all the training/data-building scripts, the measurement probes, the model
artifacts, the analytics layer, the datasets, the logs, and even the abandoned first frontend — so
nothing is a mystery.

Legend: **[runtime]** = runs in production · **[train]** = builds data / trains the model ·
**[probe]** = measures quality, never served · **[artifact]** = generated file · **[config]** ·
**[doc]** · **[data]**.

---

## 0. Repository top level

```
phishguard-ai/
├── backend/                 ← the FastAPI server, the model, all Python
├── extension/               ← the Chrome extension SOURCE (Manifest V3)
├── frontend/                ← the live web app (vanilla HTML/CSS/JS)
├── analytics/               ← Power BI star-schema exports
├── data/                    ← datasets (raw + processed)
├── docs/                    ← this documentation set
├── frontend_nextjs_backup/  ← the ABANDONED first frontend (Next.js/React) — kept for history
├── README.md                ← project readme
├── MODEL_AUDIT.md           ← the canonical retrain changelog (every metric, every version)
├── DEPLOY.md                ← deployment runbook
├── render.yaml              ← Render backend blueprint
├── vercel.json              ← Vercel frontend config
├── .gitignore               ← what's kept out of git
├── .gitattributes           ← line-ending + binary rules
└── .claude/launch.json      ← local dev preview config
```

### Root files

| File | Type | What it is |
|---|---|---|
| **README.md** | [doc] | The project's front page — what PhishGuard is, how to run it, the honest metrics, the architecture summary. |
| **MODEL_AUDIT.md** | [doc] | **The most important document in the repo.** A 68 KB running audit log of every model version (v3.0→v3.5): what changed, the exact FP/recall numbers, why each decision was made. Every metric in these docs traces back here. |
| **DEPLOY.md** | [doc] | Step-by-step deploy runbook: backend on Render first → frontend on Vercel → lock CORS to the Vercel URL, with cold-start notes and troubleshooting. |
| **render.yaml** | [config] | Render "blueprint" — declares the backend service (root `backend`, Python 3.12.1, `uvicorn main:app`, health check `/health`, `CORS_ORIGINS` env). Lets Render deploy from the repo with one click. |
| **vercel.json** | [config] | Vercel config — serves `frontend/` as static files, no build step. |
| **.gitignore** | [config] | Keeps the venv, model backups, large datasets, `.claude/`, and DB out of git. |
| **.gitattributes** | [config] | Forces LF line-endings in the repo and marks `*.pkl`/`*.zip`/`*.png` as **binary** so git never corrupts the model artifacts. |
| **.claude/launch.json** | [config] | Local dev-preview server definition (tooling only — not part of the app). |

---

## 1. `backend/` — the server, the model, all the Python

This is the heart of the project. It splits into six groups.

### 1a. Core runtime (served in production) — **[runtime]**

| File | What it does |
|---|---|
| **main.py** | The **FastAPI application**. Defines the endpoints (`POST /predict_url`, `/health`, dashboard/stats reads), runs the **6-gate detection ladder**, normalizes URLs (`_normalize_url`), does optional WHOIS/SSL enrichment, and logs every verdict. This is the file a request actually hits. → detailed in [02](02_ARCHITECTURE_FILE_BY_FILE.md) & [04](04_RULES_AND_DETECTION_LOGIC.md). |
| **predict_ml_only.py** | Loads the four model artifacts **once at startup** and exposes `predict_ml(url)`, which returns `(pred, prob, override_reason)`. Contains the three short-circuits (loopback, trusted-root, structural-critical). This is the "model" half of the system. |
| **features.py** | `extract_features(url)` → the **22 hand-engineered numeric features** (length, dots, hyphens, has-IP, `@`-in-authority, punycode, non-ASCII host, suspicious TLD, brand-spoof, …). The single source of truth for the numeric block, used identically in training and serving. |
| **config.py** | Loads `rules.json` and exposes everything tunable: the thresholds, the `FEATURE_WEIGHTS = (0.05, 0.05, 15)` triple, `stack_features()` (the weighted hstack), `trusted_roots`, `strip_www`, `csv_safe` (CSV-injection guard), the brand/keyword/TLD lists. Central config so nothing is hardcoded across files. |
| **database.py** | SQLite schema + helpers — creates the `phishing_events` table and provides `log_event(...)` and the read queries the dashboard uses. |
| **url_augment.py** | `registrable_domain()`, `has_path()`, `add_path()` — the helpers used for the **leakage-free split** (grouping by registrable domain) and the path-artifact fix during training. Also imported by tests. |
| **rules.json** | **[config/data]** All weights, thresholds, and lists as pure data — edit detection behavior **without touching code**. Enumerated in [04](04_RULES_AND_DETECTION_LOGIC.md). |
| **requirements.txt** | **[config]** The pinned dependency list (FastAPI, XGBoost, scikit-learn, scipy, numpy, pandas, rapidfuzz, python-whois, requests, pytest — exact versions). |
| **pytest.ini** | **[config]** Pytest configuration — `testpaths = tests`, quiet output, offline & deterministic so the suite gates every edit without touching the live model. |

### 1b. Model artifacts (generated by training, committed so a fresh clone runs) — **[artifact]**

| File | What it is |
|---|---|
| **model.pkl** | The trained, isotonic-**calibrated XGBoost** classifier (~1.5 MB). |
| **char_vectorizer.pkl** | The fitted **character TF-IDF** (3–5 grams, 3000 dims) — catches look-alike spellings. |
| **word_vectorizer.pkl** | The fitted **word TF-IDF** (1000 dims) — catches phishing vocabulary. |
| **scaler.pkl** | The fitted **StandardScaler** for the 22 numeric features. |
| **phishguard.db** | **[artifact/runtime]** The SQLite event log, created and appended at runtime (git-ignored). |

> These four `.pkl` files are the *frozen output* of `train_ml_strong.py`. They're committed
> (marked binary in `.gitattributes`) so the app runs immediately after `git clone` with no retrain.

### 1c. Training & data-building scripts — **[train]**

| File | What it does | Why it exists |
|---|---|---|
| **train_ml_strong.py** | **The training pipeline.** GroupShuffleSplit by registrable domain → fit vectorizers + scaler on the **train slice only** → stack weighted blocks → train XGBoost → isotonic-calibrate → save the four artifacts. | The one script that produces the model. Deterministic (seeded, `n_jobs=1`). → [03](03_MACHINE_LEARNING_FROM_BASICS.md). |
| **build_dataset.py** | Assembles `data/processed/final_dataset.csv` from the raw phishing (OpenPhish/PhishTank/active-domains) and legit sources. | Turns raw feeds into one labeled training table. |
| **build_legit_dataset.py** | Builds `legit_urls.csv` from the **Tranco Top-1M** list + a curated Indian/SaaS seed list (+ any extension false-positive reports). | Produces a clean, research-grade negative class. |
| **generate_adversarial.py** | Synthesizes adversarial phishing URLs with a **vocabulary decoupled** from `features.py`, emitting **both bare and pathed** URLs. | Fixes two training biases: the model over-fitting the 25 feature tokens, and the "has-path ⇒ phishing" artifact. |
| **harvest_fresh_data.py** | Stages **currently-active** phishing domains as a fresh training source and reserves a **disjoint holdout** (`fresh_holdout.csv`). | Targets the model's real weakness — recall on clean, brand-new bare-domain phishing — with *data*, not rules. |
| **refresh_feeds.py** | Refreshes the local blocklist from the **live OpenPhish feed**. | The shipped feed is an ~April-2025 snapshot; this pulls current live phishing so the blocklist isn't stale. |
| **export_to_bi.py** | Reads `phishguard.db` → writes the 5 star-schema CSVs in `analytics/`. | Turns the operational log into a Power BI-ready model. Uses `csv_safe` to neutralize CSV formula injection. |

### 1d. Measurement probes & diagnostics (never served) — **[probe]**

These produce the *numbers* and diagnose bugs. They share the exact serving feature weights so their
results match production. Most are summarized in [06](06_TESTING.md).

| File | What it measures / does |
|---|---|
| **fp_sweep.py** | The **gated metric** — model-only false-positive rate over **80,000 legit URLs** (must stay ≤ 9.70%; v3.5 = 6.23%). |
| **operating_point.py** | **Recall at equal FP** — the fair way to compare two model versions (not same-threshold). |
| **cross_source_recall_probe.py** | Recall on an OpenPhish feed of **novel domains the model never trained on**, blocklist/allowlist bypassed — the honest generalization test (70.4%). |
| **fresh_recall_probe.py** | Recall on the 5k unseen same-feed holdout (55.6% @ 0.60). |
| **homograph_probe.py** | The canonical **14-case** IDN/punycode + typosquat set (14/14). Also the source of truth imported by `test_model_invariants.py`. |
| **parent_path_probe.py** | The parent-vs-path bug class on non-allowlisted legit hosts (0/9 flips, was 5/9). |
| **byjus_pathfix_probe.py** | The specific byjus deep-path artifact at the model level (all SAFE). |
| **path_artifact_probe.py** | Tests identical domains **bare vs. with a path** — proves the model is no longer keying on "has a path". |
| **model_stress_test.py** | A curated realistic mix, model-only (~74–75%). |
| **keyword_rule_probe.py** | Sweeps the keyword operating point — how `KEYWORD_MIN_PROB = 0.55` was chosen. |
| **probe_model.py** | Characterizes what the trained model does on **non-allowlisted legit** companies (pure model behavior, no rules). |
| **b4_signal_probe.py** | An empirical test of whether **domain-age is a leakage artifact** of the stale snapshot (why WHOIS age was *not* folded into the model). A great example of rejecting a tempting-but-leaky feature. |
| **explain_decision.py** | Diagnostic: for any URL, prints **which tier decided** — allowlist / structural / model — and the raw calibrated probability. |
| **inspect_data.py** | Reports the training-data composition and locates the source of the path artifact. |
| **test_ml_only.py** | A **standalone** labeled sanity script (model-only predictions over a hand-built case list). Note: this is *not* part of the pytest suite in `tests/` — it's a quick manual check. |

### 1e. Logs — **[artifact]**

| File | What it is |
|---|---|
| **retrain_v32.log**, **retrain_v32b.log** | Captured console output from specific training runs — kept as an audit trail alongside `MODEL_AUDIT.md`. |

### 1f. `backend/tests/` — the pytest regression suite — **[probe]**

The 10 test files + `conftest.py` (62 functions → **128 parametrized cases**), each locking a
behavioral contract. Fully enumerated in [06_TESTING.md](06_TESTING.md#2-the-offline-pytest-suite-128-cases):
`conftest.py`, `test_features.py`, `test_feature_weights.py`, `test_config.py`,
`test_host_parsing.py`, `test_main_helpers.py`, `test_url_augment.py`, `test_model_invariants.py`,
`test_blocklist.py`, `test_blocklist_gate.py`, `test_robustness.py`.

---

## 2. `extension/` — the Chrome extension source (Manifest V3) — **[runtime]**

The **actual source** of the browser extension (the `frontend/phishguard-extension.zip` is this
folder packaged for distribution). Fully explained in [05_CHROME_EXTENSION.md](05_CHROME_EXTENSION.md).

| File | What it does |
|---|---|
| **manifest.json** | The MV3 declaration — `manifest_version: 3`, permissions (`scripting`, `storage`), `host_permissions: ["<all_urls>"]`, the service worker, the popup. |
| **background.js** | The **service worker** — listens for tab navigation, skips non-web URLs, checks each page against `/predict_url`, paints the toolbar badge, and injects the warning banner via `chrome.scripting.executeScript` + `textContent`. |
| **config.js** | `DEFAULT_API_BASE`, `getApiBase()` (storage override), `fetchWithTimeout` (8 s), and the bounded 200-entry / 60 s cache. |
| **popup.html** / **popup.js** | The toolbar popup — shows the current tab's verdict, rendered safely via `textContent` on a static scaffold. |
| **icons/icon16.png, icon48.png, icon128.png** | The extension icons at the required sizes. |

---

## 3. `frontend/` — the live web app (vanilla HTML/CSS/JS) — **[runtime]**

The deployed frontend (Vercel). No build step — plain files. → [02](02_ARCHITECTURE_FILE_BY_FILE.md).

| File | What it is |
|---|---|
| **index.html** | Landing page. |
| **url-checker.html** | The main check-a-URL page (the primary UX). |
| **dashboard.html** | The analytics dashboard (scan history / stats). |
| **extension.html** | The extension install guide (load-unpacked / zip). |
| **css/styles.css** | All styling for every page. |
| **js/env.js** | **The single deploy knob** — `window.PHISHGUARD_API_BASE = "<render URL>"`. Loaded *before* `config.js` so one edit repoints the whole frontend at the backend. |
| **js/config.js** | Resolves the API base (env.js → localStorage → localhost fallback) and shared config. |
| **js/checker.js** | The checker page logic — reads the input, calls `/predict_url`, renders the verdict card. |
| **js/dashboard.js** | The dashboard logic — fetches and renders history/stats. |
| **phishguard-extension.zip** | **[artifact]** The packaged extension (a zip of `extension/`) offered for download from `extension.html`. |

---

## 4. `analytics/` — Power BI star schema — **[artifact/doc]**

Output of `export_to_bi.py`, plus its setup guide. → the "why Power BI" rationale is in
[01](01_OVERVIEW_AND_TECH_STACK.md).

| File | What it is |
|---|---|
| **POWERBI_SETUP.md** | [doc] Step-by-step: run the export, then load the CSVs into Power BI. |
| **fact_events.csv** | The **fact table** — one row per detection event. |
| **dim_date.csv** | Date dimension (year/month/day/weekday/week). |
| **dim_type.csv** | Scan-type dimension. |
| **dim_result.csv** | Result dimension (PHISHING/SUSPICIOUS/SAFE, with display colors). |
| **kpi_summary.csv** | Pre-aggregated KPIs for quick dashboards. |

---

## 5. `data/` — the datasets — **[data]**

`data/README.md` documents exactly what's **tracked** (small, needed to run) vs **ignored** (large,
regenerable) and how to rebuild each. Dataset counts and rationale are in
[03_MACHINE_LEARNING_FROM_BASICS.md](03_MACHINE_LEARNING_FROM_BASICS.md).

| Path | Type | What it is |
|---|---|---|
| **data/README.md** | [doc] The tracked-vs-ignored table + rebuild commands. |
| **data/raw/openphish.txt** | tracked | The live-blocklist **seed** loaded at backend startup. |
| **data/raw/openphish.txt.bak_…** | tracked | A timestamped backup of a prior feed snapshot. |
| **data/raw/phishtank.csv** | ignored (large) | PhishTank phishing feed (~58k) — rebuild from the public download. |
| **data/raw/tranco.csv** | ignored (large) | Tranco Top-1M legit ranking. |
| **data/raw/kaggle.csv** | ignored (large) | Kaggle legitimate-URL set (~450k). |
| **data/raw/phishing-domains-ACTIVE.txt** | ignored (large) | Active phishing domains from the Phishing.Database project (~392k). |
| **data/processed/final_dataset.csv** | ignored (large) | The assembled ~1.5M-row labeled training table (`build_dataset.py`). |
| **data/processed/legit_urls.csv** | ignored (large) | Clean legit set (`build_legit_dataset.py`). |
| **data/processed/adversarial_phishing.csv** | tracked | Generated adversarial attacks (`generate_adversarial.py`). |
| **data/processed/fresh_phishing.csv** | ignored | Freshly harvested active phishing (`harvest_fresh_data.py`). |
| **data/processed/fresh_holdout.csv** | tracked | The 5k **disjoint holdout** for `fresh_recall_probe.py`. |
| **data/processed/tranco_top1m.zip** | ignored (large) | The raw Tranco download cache. |

---

## 6. `docs/` — this documentation set — **[doc]**

| File | Covers |
|---|---|
| **README.md** | Master index + 60-second mental model + fact sheet. |
| **01_OVERVIEW_AND_TECH_STACK.md** | What it is + every tech choice & why not the alternatives. |
| **02_ARCHITECTURE_FILE_BY_FILE.md** | Core files + the request→response lifecycle. |
| **03_MACHINE_LEARNING_FROM_BASICS.md** | ML from scratch, XGBoost, datasets, the leakage story, retrain history. |
| **04_RULES_AND_DETECTION_LOGIC.md** | The 6-gate ladder, every weight/threshold. |
| **05_CHROME_EXTENSION.md** | The extension from basics + the two security fixes. |
| **06_TESTING.md** | The 128-case suite + the statistical probes. |
| **07_INTERVIEW_QA.md** | ~80 interview questions with answers. |
| **08_RESUME_POINTS.md** | Résumé bullets + the "tell me about a project" script. |
| **09_COMPLETE_FILE_REFERENCE.md** | **This file** — every file explained. |

---

## 7. `frontend_nextjs_backup/` — the abandoned first frontend — **[history]**

This is the **original frontend, built with Next.js 14 + React 18 + TypeScript**, kept as a backup
after it was **replaced by the current vanilla-JS frontend**. It contains `pages/` (index,
url-checker, dashboard, extension), `components/` (Navbar, ResultCard), `styles/`, `package.json`
(next/react/react-dom deps), `tsconfig.json`, and a `.next/` build-cache directory.

> **Why this matters for interviews:** it's the *evidence* behind the "why vanilla JS, not React"
> answer ([Q13](07_INTERVIEW_QA.md)). You didn't dismiss React out of hand — you **actually built the
> frontend in Next.js first, then deliberately moved to vanilla JS** to eliminate the build step, the
> bundler, and the dependency tree for what is really a few forms and result cards, and so the same
> code could run in the extension. That's a real, defensible engineering decision, not a preference.
> The `.next/` folder is just build cache (git-ignored) and can be deleted.

---

## 8. Generated / ignored directories (not in git)

You'll see these locally but they're **git-ignored** — regenerated, not source:

| Path | What it is |
|---|---|
| **venv/** or **.venv/** | The Python virtual environment (created from `requirements.txt`). |
| **__pycache__/** | Python bytecode caches. |
| **.pytest_cache/** | Pytest's run cache. |
| **model_backup_v34_…/**, **model_backup_v35_…/** | **Pre-retrain snapshots** of the model artifacts — the safety net behind "every retrain is backed up first and reverted if it regresses the FP gate". |
| **.git/** | The git repository metadata. |

---

## How doc 02 and doc 09 differ

- **[02](02_ARCHITECTURE_FILE_BY_FILE.md)** = *depth on the runtime path* — how a request flows
  through `main.py` → the gates → the model → the response, with the connections that matter.
- **[09](09_COMPLETE_FILE_REFERENCE.md)** (this) = *breadth over every file* — so when an interviewer
  points at any filename in the repo, you can say exactly what it is and why it's there.

Together they mean **there is no file in this project you can't explain.**
