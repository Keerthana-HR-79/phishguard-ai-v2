# 🛡️ PhishGuard AI

**Real-time phishing URL detection — a calibrated XGBoost model wrapped in a
reputation + structural-rule safety net, with a web UI, Chrome extension and
Power BI analytics.**

The interesting part of this project isn't a headline accuracy number — it's that
the headline accuracy number was a **lie**, and most of the engineering went into
finding out why and reporting an honest one. See [§ The honest-metrics story](#-the-honest-metrics-story).

---

## 🏗️ Project structure

```
phishguard-ai/
├── backend/                    ← FastAPI Python backend
│   ├── main.py                 ← API + 4-gate serving pipeline (/predict_url /stats /recent /health)
│   ├── features.py             ← 22-feature URL extractor (+ punycode/IDN homograph decode)
│   ├── config.py               ← Loads rules.json (lists, weights, thresholds)
│   ├── predict_ml_only.py      ← Raw model scorer (XGBoost + char/word TF-IDF + scaler)
│   ├── train_ml_strong.py      ← Train the model (grouped split, path decorrelation, label cleaning)
│   ├── url_augment.py          ← Train-time URL augmentation (symmetric path decorrelation)
│   ├── refresh_feeds.py        ← Pull the live OpenPhish feed into the local blocklist
│   ├── rules.json              ← Central config: brands, keywords, TLDs, trusted roots, weights, thresholds
│   ├── model.pkl               ← Trained XGBoost model (+ char_vectorizer / word_vectorizer / scaler .pkl)
│   ├── tests/                  ← 128 offline pytest regression tests
│   └── *_probe.py / fp_sweep.py / operating_point.py  ← measurement tools (see below)
│
├── data/
│   ├── raw/                    ← openphish.txt, phishtank.csv, tranco.csv, Phishing.Database ACTIVE
│   └── processed/              ← final_dataset.csv, fresh_phishing.csv, fresh_holdout.csv, adversarial_phishing.csv
│
├── frontend/                   ← Static site (vanilla HTML/CSS/JS — no build step)
│   ├── index.html url-checker.html dashboard.html extension.html
│   ├── css/styles.css
│   ├── js/{config,checker,dashboard}.js
│   └── phishguard-extension.zip   ← downloadable Chrome extension (built from extension/)
│
├── extension/                  ← Chrome Extension (Manifest V3)
│   ├── manifest.json popup.html popup.js background.js icons/
│
├── analytics/                  ← Power BI setup + exported star-schema CSVs
│   └── POWERBI_SETUP.md
│
├── MODEL_AUDIT.md              ← full model changelog v3.0 → v3.5 + every measurement
└── README.md
```

---

## 🧠 How it works — the 4-layer pipeline

A URL is judged by four layers, in order. **The model is the decider; the other
three layers exist to cover its two structural blind spots** (see below).

```
URL ─▶ normalize ─▶ allowlist (known good → SAFE) ─▶ ML model (the decider) ─▶ rule ladder (structural overrides + decisive blocklist + weighted signals) ─▶ verdict + reasons ─▶ SQLite ─▶ dashboard / Power BI
```

1. **Normalize** — de-fang (`hxxp→http`, `[.]→.`), collapse duplicate slashes, cap length. Blocks trivial evasion.
2. **Allowlist** (exact registrable-root match, instant): 245 curated trusted roots → SAFE *before the model runs*. This is the false-positive guard for well-known real sites.
3. **ML model** — for everything unknown, a calibrated XGBoost classifier scores the URL `0–1` from 22 hand-built features + character-level TF-IDF + word-level TF-IDF.
4. **Rule ladder** (`main.py`, laddered gates): first, absolute overrides for unambiguous structural tells (raw-IP host, `@`-in-authority credential trick) → PHISHING. Then an **exact** match against the local ~76k-URL known-phishing blocklist (live OpenPhish/PhishTank, refreshable via `refresh_feeds.py`) is a **decisive PHISHING verdict** — not the old weak weighted signal. That blocklist match overrides the allowlist *only* for **shared-hosting commons** (`github.io`, `*.blogspot.com`, `wordpress.com`, … where the trust belongs to the platform, not the tenant), and **never** for a real brand root (`google.com`, `paypal.com`), so a stale feed entry can't flip a brand. Then the **allowlist verdict is honored as SAFE** (so a legit page like `microsoft.github.io` is never dragged to SUSPICIOUS by the brand/subdomain heuristics). Finally, a confident-safe fast path and a weighted heuristic score handle the uncertain middle.

### Why keep rules if the model is good?

Because a **URL-string-only** model has two blind spots that no amount of training removes:

- A **brand-new, tell-free domain** (`fakebrand123.com`) — nothing in the string gives it away → covered by the **blocklist**.
- **Compromised-host phishing** on a legitimately-owned domain (a hacked WordPress page) — the registrable root is real, so the string looks fine → covered by the **blocklist**; the model correctly does *not* fire on it (16–21% of live-feed phishing is this shape).

This is defense-in-depth, and each layer is measured separately so its contribution is known.

---

## 📊 The honest-metrics story

An early version of this project reported **98.1% accuracy**. That number came from a
train/test split that **leaked domains across both sides** and keyed on dataset
artifacts (e.g. "URL has a path ⇒ phishing"). It was retired. Three artifacts were
found and fixed:

| Artifact | Fix |
|---|---|
| Model learned *"has a path ⇒ phishing"* (legit data was bare domains, phishing was pathed) | Symmetric train-time path augmentation for **both** classes (`url_augment.py`) |
| Phishing vocabulary was the *same word list* the features counted (circular) | Decoupled the adversarial-generation vocabulary from the feature vocabulary |
| Train/test split leaked the same domain into both sides | `GroupShuffleSplit` grouped by registrable domain; disjoint train/calibrate/test, with vectorizers + scaler fit on the **train slice only** (no preprocessing leakage) |

**Honest, leakage-free numbers (model measured in isolation, rules bypassed):**

| Metric | Value | How it's measured |
|---|---|---|
| Model-only false-positive rate | **6.2%** | 80,110-URL legit sweep (`fp_sweep.py`) — down from 10.4% |
| Cross-source recall, all live-feed URLs | **78.2%** | OpenPhish, a feed the model never trained on (`cross_source_recall_probe.py`) |
| Cross-source recall, **novel roots** (zero leakage) | **70.4%** | OpenPhish URLs whose registrable root was never in training |
| Same-feed bare-domain recall | **55.6%** | 5k unseen bare-domain holdout (`fresh_recall_probe.py`) — the *hardest* slice |
| Homograph / typosquat detection | **14 / 14** | dedicated probe (`homograph_probe.py`) |
| Offline regression suite | **128 passed** | `cd backend && python -m pytest` |

> **Honest caveat, stated plainly:** a completely tell-free brand-new domain is a hard
> URL-lexical ceiling no URL-only model repeals — that case is handled at runtime by the
> live blocklist, not the model. Full changelog and every measurement: [`MODEL_AUDIT.md`](MODEL_AUDIT.md).

---

## 🚀 Quick start

### 1. Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
Test it:
```bash
curl -X POST http://localhost:8000/predict_url -H "Content-Type: application/json" -d "{\"url\": \"https://paypa1-secure.xyz/login\"}"
```

### 2. Frontend (no build step)
```bash
cd frontend
python -m http.server 3000
```
Open http://localhost:3000 — the API base URL lives in `frontend/js/config.js`.

### 3. Chrome extension
Download it from the site's Extension page (or zip the `extension/` folder), then in
`chrome://extensions` enable **Developer mode → Load unpacked → select the folder**.
The extension checks every tab against the backend on port 8000 and injects a warning
banner on phishing pages.

### 4. Power BI
```bash
cd backend && python export_to_bi.py
```
Then follow [`analytics/POWERBI_SETUP.md`](analytics/POWERBI_SETUP.md).

### Retrain the model (optional — a trained `model.pkl` ships with the repo)
```bash
cd backend
python train_ml_strong.py     # grouped split, split-then-fit (no leakage), deterministic
python -m pytest              # 128 offline regression tests must stay green
python fp_sweep.py            # model-only FP rate must not regress past ~9.7%
```

---

## 📡 API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/predict_url` | Check a URL — returns verdict, risk score, reasons, ML probability |
| GET | `/stats` | Dashboard KPIs |
| GET | `/recent?limit=20` | Recent detection events |
| POST | `/report_false_positive` | Report a wrongly-flagged URL |
| GET | `/health` | `{version, model, decision_threshold, keyword_min_prob}` |

> ⚠️ **Security note (by design):** the API is **unauthenticated** — it's an internal
> demo service. For production you'd put it behind an API key/gateway, rate-limit
> `/predict_url`, and tighten CORS (already env-overridable via `CORS_ORIGINS`).

### Example response — `/predict_url`
```json
{
  "type": "url",
  "input": "https://paypa1.com@secure-update.xyz",
  "domain": "secure-update",
  "ml_probability": 0.999,
  "risk_score": 10.0,
  "result": "PHISHING",
  "reasons": ["Critical: Structural security risk detected (@ credential trick)"],
  "meta": { "domain_age_days": -1, "ssl_valid": null }
}
```

---

## 🧪 Measurement tooling

This project treats every claim as something to measure, not assert. Each tool is
read-only and shares the exact train/serve feature invariant, so results are
reproducible after any retrain:

| Tool | Answers |
|---|---|
| `fp_sweep.py` | Model-only false-positive rate on 80k legit URLs (the gate: must stay ≤ 9.7%) |
| `operating_point.py` | Recall vs FP frontier — proves one model dominates another at equal FP |
| `cross_source_recall_probe.py` | Honest recall on an **independent** feed (novel-root, zero-leakage) |
| `fresh_recall_probe.py` | Bare-domain recall on an unseen holdout |
| `homograph_probe.py` | Punycode / IDN / typosquat detection (14 curated cases) |
| `parent_path_probe.py` | Parent-domain-SAFE vs deep-path over-flagging on non-allowlisted legit hosts |
| `keyword_rule_probe.py` | Full-pipeline recall/FP trade of the keyword heuristic threshold |

---

## 📋 Tech stack

| Layer | Technology |
|-------|-----------|
| ML | XGBoost + isotonic calibration + char/word TF-IDF + 22 hand-crafted features |
| Backend | FastAPI + Python 3.12 |
| Database | SQLite (scan history + stats) |
| Frontend | Vanilla HTML/CSS/JS (no framework, no build step) |
| Extension | Chrome MV3 (Manifest V3) |
| Analytics | Power BI Desktop + DAX + Power Query (star schema) |
| Data pipeline | pandas + scikit-learn + xgboost |

---

## 💬 Interview pitch

> "I built PhishGuard AI, a real-time phishing URL detector. The technically interesting
> part: the first version reported 98% accuracy, and I found that was an artifact of
> domain leakage and dataset shortcuts in the train/test split. I rebuilt the evaluation
> to be leakage-free (grouped by domain), fixed three dataset artifacts, and reported
> honest numbers — 6.2% model-only false-positive rate and ~70–78% recall on a phishing
> feed the model had never seen. Then, because a URL-string-only model has a hard lexical
> ceiling, I wrapped it in a reputation blocklist and a structural-rule layer as
> defense-in-depth, and measured what each layer contributes. It ships with a web UI, a
> Chrome extension, a live analytics dashboard, Power BI reporting, and a 128-test
> regression suite that locks every invariant."
