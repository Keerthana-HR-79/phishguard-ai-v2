# PhishGuard AI — Complete Project Documentation

This folder is a **from-basics, end-to-end explanation** of the entire PhishGuard AI
project: every technology and *why* it was chosen (and why not the alternatives), every
file and how it connects, the full request→response lifecycle, the machine-learning core
explained from first principles, the complete detection-rule ladder, the Chrome extension,
the test suite, and ready-to-use interview answers and resume bullets.

It is written to be read start-to-finish for deep understanding, or dipped into per-topic
for interview revision.

---

## The 60-second mental model

**What it is:** a real-time phishing-URL detector. You give it a URL; it returns a verdict
(`SAFE` / `SUSPICIOUS` / `PHISHING`), a 0–10 risk score, and the exact reasons.

**How it decides (one sentence):** a **calibrated XGBoost machine-learning model** scores
the URL first, and a thin **6-gate rule ladder** wraps that score to handle the cases a
URL-string model provably cannot (known-bad blocklist, globally-trusted allowlist,
structural attacks like raw-IP or `@`-credential tricks).

**Three surfaces, one brain:**
1. A **web app** (URL checker + analytics dashboard) — vanilla HTML/CSS/JS.
2. A **Chrome extension** (Manifest V3) that checks every page you visit in the background.
3. A **FastAPI backend** that both of the above call — it holds the model and the rules.

**The honest headline number:** on a leakage-free, domain-grouped hold-out set the model
alone generalizes at **~74% accuracy**; its **false-positive rate is 6.23%** on an 80,000-URL
legit sweep; it catches **~70% of never-before-seen phishing** from a feed it never trained
on. It is deliberately **not** the retired, dishonest "98%" (which was inflated by data
leakage — that story is a *strength* to tell, see below).

---

## The documents

| # | File | What it covers |
|---|------|----------------|
| 00 | **[README.md](README.md)** (this file) | Orientation, the 60-second model, the fact sheet |
| 01 | **[01_OVERVIEW_AND_TECH_STACK.md](01_OVERVIEW_AND_TECH_STACK.md)** | What the project is, the architecture diagram, **every tech choice + why it and not the alternatives** (FastAPI vs Flask/Django/Node, XGBoost vs LogReg/RandomForest/Deep Learning, SQLite vs Postgres, vanilla JS vs React, etc.) |
| 02 | **[02_ARCHITECTURE_FILE_BY_FILE.md](02_ARCHITECTURE_FILE_BY_FILE.md)** | Every file explained, the **full request→response lifecycle**, the 6-gate serving ladder, the database, the analytics/Power BI layer, deployment |
| 03 | **[03_MACHINE_LEARNING_FROM_BASICS.md](03_MACHINE_LEARNING_FROM_BASICS.md)** | Supervised vs unsupervised, the 22 features, the datasets (with exact counts), TF-IDF, scaling, **how XGBoost works from basics** (trees→boosting→gradient boosting→regularization), calibration, **how the model is trained**, the leakage story, the **full v3.0→v3.5 retrain history with exact metrics**, how it detects & classifies |
| 04 | **[04_RULES_AND_DETECTION_LOGIC.md](04_RULES_AND_DETECTION_LOGIC.md)** | Every rule, weight and threshold; the 6 gates in full; homograph/IDN detection; why rules exist alongside the model |
| 05 | **[05_CHROME_EXTENSION.md](05_CHROME_EXTENSION.md)** | Manifest V3 from basics: service worker, popup, content injection, the CSP/XSS fixes, how it talks to the backend |
| 06 | **[06_TESTING.md](06_TESTING.md)** | The 128-case offline regression suite explained file-by-file; the statistical probes (fp_sweep, operating_point, cross_source); what "regression testing" means here |
| 07 | **[07_INTERVIEW_QA.md](07_INTERVIEW_QA.md)** | ~80 anticipated interview questions with model answers, from beginner to hard |
| 08 | **[08_RESUME_POINTS.md](08_RESUME_POINTS.md)** | Exact resume bullets, the "tell me about a project" script, and the strongest lines to mention |
| 09 | **[09_COMPLETE_FILE_REFERENCE.md](09_COMPLETE_FILE_REFERENCE.md)** | **Every single file and folder in the repo explained** — core runtime, model artifacts, all training/data-building scripts, every measurement probe, the datasets, analytics, logs, and the abandoned Next.js first frontend. Doc 02 is depth-on-the-runtime; this is breadth-over-everything |
| 10 | **[10_FILE_BY_FILE_DEEP_DIVE.md](10_FILE_BY_FILE_DEEP_DIVE.md)** | **The depth map** — for every logic-bearing file, its **actual functions with signatures, the real logic inside them, inputs/outputs, and the import graph** (what wires to what). Doc 09 tells you *that* a file exists; this lets you *walk through* it. Start with the runtime import-graph diagram at the top |
| 11 | **[11_CODE_WALKTHROUGH.md](11_CODE_WALKTHROUGH.md)** | **The annotated real code** — opens each file and walks the *actual source* (copied verbatim, trimmed only with `…`) with line-group commentary: two wiring maps (runtime import graph + training data flow), then config/features/predict/main's 6 gates/augment/database/trainer/fp_sweep/extension, then a single end-to-end `/predict_url` request trace. Doc 10 lists the functions; this reads the lines with you |
| — | **[RESUME_CHEATSHEET.md](RESUME_CHEATSHEET.md)** | **Interview-day one-pager** — the verified résumé header, 5 ready bullets, a skills line, and a per-keyword *"if they ask X, say Y"* defense sheet, plus 6 honesty rules. Every line checked against the code (128 pytest passing); the honest ~74%/6.2%-FP/70% numbers, never the retired 98% |

---

## Fact sheet (quick reference)

**Versions (live):** backend **v3.2.0**, model **v3.5**, decision threshold **0.60**,
keyword-rule threshold **0.55**.

**Stack:** Python 3.12.1 · FastAPI · XGBoost (calibrated) · scikit-learn · scipy · rapidfuzz ·
SQLite · vanilla HTML/CSS/JS · Chrome MV3 extension · Power BI (CSV star-schema export) ·
pytest · deployed on Render (backend) + Vercel (frontend), private GitHub repo.

**The model:** supervised **binary classifier**; calibrated **XGBoost** over
**22 hand-built URL features** + **character TF-IDF** (3-5 grams, 3000 dims) + **word TF-IDF**
(1000 dims), block-weighted `[0.05, 0.05, 15]`, isotonic-calibrated.

**Key metrics (model-only, honest):**
- False-positive rate: **6.23%** on an 80,110-URL legit sweep (hard ceiling was ≤ 9.70%).
- Cross-source recall (unseen feed *and* unseen domain): **~70.4%**.
- Homograph/typosquat probe: **14/14**.
- Grouped hold-out accuracy: **~74%** (leakage-free).
- Retired dishonest number: ~98% (was inflated by domain leakage — never claim it).

**Datasets (columns `url,type`):**
- `final_dataset.csv` — **1,508,510** rows (~1,345,737 legitimate + ~162,313 phishing).
- `fresh_phishing.csv` — **154,798** freshly-mined novel+clean phishing roots.
- `legit_urls.csv` — **80,111** curated legit URLs (the FP sweep set).
- `adversarial_phishing.csv` — **11,930** synthesized brand/keyword spoofs.
- `fresh_holdout.csv` — **5,001** unseen phishing domains (never trained on).
- Raw feeds: OpenPhish (`openphish.txt`), PhishTank, Tranco (1M), Kaggle, Phishing.Database ACTIVE (391,986).

**Tests:** **128** passing pytest cases across 11 files + statistical probes.

**The 6-gate serving ladder** (order matters): 1) ML model score → 2) structural-critical
override (raw-IP / `@`-authority) → 2b) decisive blocklist → 2c) trusted-root allowlist SAFE
→ 3) confident-safe fast path → 4) weighted heuristics + confidence dampener.

---

## The one thing to lead with in an interview

> "The most valuable thing I did wasn't getting a high accuracy number — it was **catching that
> my high accuracy number was a lie.** My first model reported ~98%, but I audited it and found
> the test set shared domains with the training set (data leakage), plus a shortcut where 'URL
> has a path' was standing in for 'phishing'. I rebuilt the evaluation with a domain-grouped
> split, killed the leakage, and got an *honest* ~74% — then spent five documented retrains
> genuinely improving it: false positives from 10.4% down to 6.2%, and unseen-phishing recall
> up 2.5×. I can walk you through every version and the exact metric that moved."

That single narrative demonstrates ML maturity most student projects never show. Details in
[03_MACHINE_LEARNING_FROM_BASICS.md](03_MACHINE_LEARNING_FROM_BASICS.md) and
[07_INTERVIEW_QA.md](07_INTERVIEW_QA.md).
