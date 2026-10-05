# PhishGuard AI — Complete Interview Prep (the everything, parts-wise bible)

*The single consolidated study document. Pulls together the master guide, the ML deep-dive, and the line-by-line résumé defense into one parts-wise file, plus an exhaustive question bank. Every claim verified against the actual source: backend v3.2.0, model v3.5, 128 pytest passing.*

### The tag system (used everywhere below)
| Tag | Meaning |
|---|---|
| 🟢 **ON RESUME** | The exact claim in your bullet. Defend it word-for-word. |
| 🔵 **LEARN DEEP** | The concept underneath the word (from basics). Not on the résumé, but needed to survive the follow-up. |
| ⚠️ **HONEST LIMIT** | A real weakness to admit cleanly — admitting it makes you sound senior. |
| 💻 **CODE** | Where it lives and what the code does. |

**Golden rule:** everything you say maps to a file, a number, or a reproducible test. If you can't back it, don't say it.

---

## PARTS INDEX
- **Part 0** — Your résumé block (exact words) + study map
- **Part 1** — The pitches (10-sec, 60-sec, 2-min)
- **Part 2** — BULLET 1 defense (Machine Learning / XGBoost / trained / features)
- **Part 3** — BULLET 2 defense (FastAPI / SQLite / Chrome MV3 / real-time)
- **Part 4** — BULLET 3 defense (hybrid pipeline / blocklist / allowlist / homograph)
- **Part 5** — ML concepts from basics (the full glossary)
- **Part 6** — The dataset, in full
- **Part 7** — The 22 engineered features, in full
- **Part 8** — TF-IDF from basics
- **Part 9** — XGBoost from a single tree up
- **Part 10** — Calibration from basics
- **Part 11** — The training pipeline (9 steps, with code)
- **Part 12** — Data leakage (your strongest story)
- **Part 13** — The 6-gate serving pipeline (with code)
- **Part 14** — Homograph detection (with code)
- **Part 15** — End-to-end walkthrough (3 traced URLs)
- **Part 16** — The honest numbers (every metric)
- **Part 17** — Testing & deployment
- **Part 18** — Full tech stack
- **Part 19** — THE QUESTION BANK (every question that can arise, with answers)
- **Part 20** — Honesty rules / traps
- **Part 21** — Rapid-fire flashcards

---

## PART 0 — Your résumé block & study map

**Header:**
> **PhishGuard AI — Phishing Detection System** | *Python, Machine Learning, FastAPI, XGBoost, Chrome Extension*

**Bullets:**
> 1. Developed an end-to-end phishing URL detection system using a **machine learning** model (**XGBoost**) **trained** on engineered URL features.
> 2. Built a **FastAPI** backend with **SQLite** event logging and a **Chrome (Manifest V3)** extension for real-time URL scanning and in-page phishing warnings.
> 3. Designed a hybrid detection pipeline combining the ML model with a **blocklist**, a trusted-domain **allowlist**, and **homograph detection** for look-alike domains.

**Study order:** master every 🟢 (you can't put a word on your résumé you can't defend) → then every 🔵 (these *will* come up) → the leakage story (Part 12) until you can tell it in 20 seconds → the end-to-end walkthrough (Part 15) → skim the rest.

**The one-line project definition:** a supervised ML system that classifies a URL as phishing or legitimate in real time, wrapped in a rule ladder that handles the cases a URL-only model provably can't.

---

## PART 1 — The pitches

**10-second (the hallway version):**
> "PhishGuard is a real-time phishing-URL detector — a calibrated XGBoost model trained on ~1.5M URLs, wrapped in a rule pipeline and exposed through a FastAPI backend and a Chrome extension."

**60-second (the standard open):**
> "You give it a URL and it returns SAFE, SUSPICIOUS, or PHISHING with a 0–10 risk score and the exact reasons. The core is a machine-learning model — a calibrated XGBoost classifier trained on about 1.5 million labelled URLs using features I engineered from the URL string. But a URL-string model alone can't know a site is on a live blacklist, and it must never flag google.com, so I wrapped it in a rule pipeline: the model scores first, then gates handle the certainties — a known-bad blocklist, a trusted-domain allowlist, and structural red flags like raw-IP hosts or look-alike homograph domains. It's exposed three ways: a FastAPI backend holding the model, a web dashboard, and a Chrome Manifest-V3 extension. Scans are logged to SQLite. The part I'm proudest of isn't a high accuracy number — it's that I caught my own accuracy number being a lie: my first model reported ~98%, I audited it, found data leakage, fixed the evaluation, and reported an honest ~74%."

**2-minute:** expand the 60-sec by adding (a) the feature blocks — 22 engineered numeric + char/word TF-IDF, (b) the leakage detail — domain leakage + path artifact, (c) the metrics — 6.23% false-positive rate on 80k legit URLs, ~70% cross-source recall, and (d) the two Chrome MV3 security bugs you fixed.

---

## PART 2 — BULLET 1 defense (the Machine Learning bullet)

> *"Developed an **end-to-end** phishing URL detection system using a **machine learning** model (**XGBoost**) **trained** on **engineered URL features**."*

### 2.1 — "machine learning"
**🟢 Say:** "Supervised binary classification — I trained on URLs each labelled phishing or legitimate; it predicts which a new URL is, as a probability 0–1."
**🔵 Deep:** ML = learn the pattern from labelled examples instead of hand-writing rules. *Supervised* = every example has the right answer. *Binary classification* = two classes. *Unsupervised* (the contrast) = no labels, finds structure itself — not used because I had labels.
**💻 Code:** `train_ml_strong.py` — labels come from the dataset `type` column into `y`; `model.fit(X_train, y_train)`.
**⚠️ Limit:** "It only sees the URL string, never page content — a clean-looking brand-new malicious URL is a real blind spot, which is why the blocklist sits beside it."

### 2.2 — "XGBoost"
**🟢 Say:** "Gradient-boosted decision trees — an ensemble that builds many small trees in sequence, each correcting the previous ones' errors."
**🔵 Deep (build from basics):** decision tree → ensemble → boosting (sequential, error-correcting) → gradient boosting (each tree fits the gradient of the loss) → XGBoost = that + regularization + speed. Full version in Part 9.
**💻 Code (`train_ml_strong.py`):**
```python
base_model = XGBClassifier(
    n_estimators=400,      # 400 boosting rounds (trees)
    max_depth=7,           # up to 7 nested questions → captures interactions
    learning_rate=0.05,    # each tree adds 5% → slow, stable, less overfit
    scale_pos_weight=1,    # no reweighting — data already balanced 50/50
    eval_metric="logloss", # right loss for probabilistic classification
    random_state=42, n_jobs=1, verbosity=0,  # deterministic + reproducible
)
```
**⚠️ Limit:** "Hyperparameters are standard + light hand-tuning, not an exhaustive grid search — that's the obvious next step."

### 2.3 — "trained"
**🟢 Say:** "Trained on ~1.5M labelled URLs, balanced 50/50, split **by domain** so it's tested on domains it never saw."
**🔵 Deep:** train/test split (learn on one slice, measure on another); class balance (else a lazy model scores high by always guessing the majority); GroupShuffleSplit by registrable domain (keeps all URLs of a domain on one side); fit transforms on train only (else test info leaks).
**💻 Code:** the 9-step pipeline — see Part 11.
**⚠️ Limit:** "1.5M is aggregated from public feeds (PhishTank, OpenPhish, Kaggle, Tranco), so it carries those feeds' biases — not a random sample of the web."

### 2.4 — "engineered URL features"
**🟢 Say:** "22 hand-built numeric features — length, digit count, entropy, suspicious-TLD flag, brand-similarity, the `@`-trick, punycode — combined with character and word TF-IDF."
**🔵 Deep:** feature = a number describing the input; feature engineering = designing those numbers from domain knowledge; feature vector = the full list for one URL. TF-IDF + StandardScaler explained in Parts 8 and 5.
**💻 Code (`features.py` + `config.py`):** `extract_features(url)` returns 22 numbers (full table in Part 7); the three blocks are weighted and stacked in one shared function:
```python
FEATURE_WEIGHTS = (0.05, 0.05, 15)   # (char-TFIDF, word-TFIDF, numeric)
def stack_features(x_char, x_word, x_num):
    return hstack([x_char*0.05, x_word*0.05, x_num*15]).tocsr()
```
**Say:** "Numeric weighted 15, TF-IDF 0.05 — my engineered features carry the decision; TF-IDF is a *secondary* look-alike signal. Same function at train and serve, so the vector can't drift."
**⚠️ Limit:** "The 0.05/15 weights are hand-set, not learned — learning them is documented future work; I don't oversell TF-IDF."

### 2.5 — "calibrated" (the hidden word)
**🟢 Say:** "It's *calibrated* XGBoost — isotonic calibration remaps raw scores to honest probabilities, because my thresholds (0.60 flag, 0.35 fast-pass) are probability thresholds."
**💻 Code:** `CalibratedClassifierCV(base_model, cv="prefit", method="isotonic")` fit on a **disjoint** calibration slice. Full version in Part 10.
**⚠️ Limit:** "Isotonic can overfit on a small calibration set; mine's large enough, but that's the trade-off vs. the simpler sigmoid method."

### 2.6 — "end-to-end"
**🟢 Say:** "The whole path: raw URL → normalize → extract features → model scores → rule gates → verdict + risk score + reasons → logged to SQLite → shown in the web app and the Chrome extension." (Traced in Part 15.)

---

## PART 3 — BULLET 2 defense (the engineering bullet)

> *"Built a **FastAPI** backend with **SQLite** event logging and a **Chrome (Manifest V3)** extension for **real-time URL scanning** and **in-page phishing warnings**."*

### 3.1 — "FastAPI backend"
**🟢 Say:** "Async Python framework holding the model, exposing `/predict_url`. I chose it over Flask for built-in async, automatic Pydantic validation, and auto-generated docs."
**🔵 Deep:** `async def` lets the server handle other requests while one waits on slow I/O; CPU/network work must be pushed off the event loop; Pydantic validates the request shape automatically.
**💻 Code (`main.py`):**
```python
@app.post("/predict_url")
async def predict_url(req: URLRequest):            # Pydantic validates req.url
    url = _normalize_url(req.url)                  # de-fang hxxp/[.], cap length
    pred, prob, reason = await asyncio.to_thread(predict_ml, url)  # model off the loop
    ...                                            # the 6 gates (Part 13)
    _log_event_safe(...)                           # SQLite write, never crashes a scan
    return {...}
```
`asyncio.to_thread` is the key line — the CPU-bound model runs in a worker thread so the async loop stays responsive.
**⚠️ Limit:** "Single-process dev setup (`uvicorn --reload`). Production needs multiple workers behind a process manager plus rate-limiting."

### 3.2 — "SQLite event logging"
**🟢 Say:** "Every scan logs the URL, verdict, risk score, response time, and timestamp — powering the analytics dashboard and a Power BI export."
**🔵 Deep:** SQLite = serverless single-file SQL DB; parameterized `?` queries prevent SQL injection; indexes keep the dashboard queries fast.
**💻 Code (`database.py`):**
```python
CREATE TABLE IF NOT EXISTS phishing_events (id, type, content, result, risk_score, response_time, timestamp)
conn.execute("INSERT ... VALUES (?, ?, ?, ?, ?, ?)", (...))   # injection-safe
content[:500]     # cap stored URL
init_db()         # auto-creates on import; contextlib.closing ensures the conn closes
```
**⚠️ Limit:** "SQLite is single-writer — fine here; for real concurrency I'd move to Postgres. `DB_PATH` is an env var so that swap is one line."

### 3.3 — "Chrome (Manifest V3) extension"
**🟢 Say:** "MV3 is Chrome's current security model — a background service worker calls my API per page, and a content script injects an in-page warning banner on a flag."
**🔵 Deep:** MV3 replaced persistent background pages with ephemeral **service workers** and tightened the CSP (no running strings as code); a **content script** touches the page DOM; the **service worker** does the network call.
**💻 Code — the two security bugs you fixed (great story):**
```js
// BUG 1 (CSP): new Function(...)   ❌ banned in MV3 → chrome.scripting.executeScript ✅
// BUG 2 (DOM-XSS): el.innerHTML = reason ❌ → el.textContent = reason ✅ (renders as text)
```
**⚠️ Limit:** "It's **built and loaded unpacked** — not published to the Web Store. So 'built,' not 'deployed to users,' and it currently calls my local API."

### 3.4 — "real-time URL scanning"
**🟢 Say:** "One URL scored synchronously in well under a second; only optional WHOIS/SSL enrichment is slow, so it's cached and run off the event loop."
**💻 Code:** WHOIS/SSL via `asyncio.to_thread` with a TTL cache (`META_CACHE_TTL_SEC = 900`).
**⚠️ Limit:** "The first scan of a brand-new domain can be slower if WHOIS is cold; after caching it's instant. Real-time per-URL, not a bulk engine."

---

## PART 4 — BULLET 3 defense (the hybrid-pipeline bullet)

> *"Designed a **hybrid detection pipeline** combining the ML model with a **blocklist**, a trusted-domain **allowlist**, and **homograph detection** for look-alike domains."*

### 4.1 — "hybrid detection pipeline"
**🟢 Say:** "Model-first, rules-as-guardrails: the model scores first, then a ladder of gates handles the certainties a URL-only model can't — a live known-bad list, a trusted allowlist, hard structural red flags."
**🔵 Deep:** a model is probabilistic; some facts are certain (this exact URL is blacklisted; this host is a raw IP; this is google.com). Encoding certainties as rules is more correct and explainable than hoping the model learned them. Defense-in-depth = layered checks.
**💻 Code:** the 6 gates — see Part 13.
**⚠️ Limit:** "Rules can be gamed if an attacker knows them and need upkeep — which is why the generalizing ML model is the first gate, not the rules."

### 4.2 — "blocklist"
**🟢 Say:** "A local union of OpenPhish + PhishTank feeds, as a decisive gate on an **exact URL match** — not substring or domain."
**🔵 Deep:** domain/substring matching would condemn a whole shared host (one bad `sites.google.com/x` page ≠ all of google.com). Exact-URL match flags only the known-bad page. The **shared-hosting carve-out**: for user-content hosts, a blocklist hit overrides the allowlist.
**💻 Code (`main.py` `check_blocklist`):** normalize then exact-membership check in the in-memory set; `SHARED_HOSTING_ROOTS` is asserted (in `config.py`) to be a subset of `TRUSTED_ROOTS` so Gate 2b can beat Gate 2c.
**⚠️ Limit:** "It's a **point-in-time snapshot**, not a live API — phishing URLs rotate in hours. Refreshable (`refresh_feeds.py`), but a live feed is the real fix."

### 4.3 — "trusted-domain allowlist"
**🟢 Say:** "A small allowlist of globally trusted roots; if the registrable domain is on it, it short-circuits to SAFE *before* the model runs — so I can never flag the real PayPal."
**🔵 Deep — 'isn't allowlisting cheating?':** "It's a safety net, not the classifier. I measure model quality *without* it — the 6.23% false-positive rate is model-only — so I always know real model performance."
**💻 Code (`predict_ml_only.py`):**
```python
if host in TRUSTED_ROOTS:
    return (0, 0.001, "Globally trusted domain")   # SAFE fast-path, model never runs
```
Matching is on the parsed host (`parse_host`), never a substring — so `http://evil.tk/google.com` can't fake in.
**⚠️ Limit:** "An allowlist is manual and always incomplete — top brands only, not the long tail. Deliberately small to avoid a maintenance burden."

### 4.4 — "homograph detection for look-alike domains"
**🟢 Say:** "Homograph/IDN attacks use look-alike characters — a Cyrillic 'а' in 'pаypal', or punycode `xn--`. I decode punycode, fold confusables to a plain-ASCII skeleton, then fuzzy-match against my brand list."
**🔵 Deep:** IDN/punycode (`xn--pypal-4ve.com` displays as pаypal); confusable folding/skeleton (NFKD + a confusables map collapses the disguise); fuzzy matching (`rapidfuzz`, `paypa1` ≈ `paypal`). Full version in Part 14.
**💻 Code (`features.py`):** `_decode_idn(host)`, `_skeleton(s)`, feature 20 (`xn--` present), feature 21 (non-ASCII host after decode), feature 7 (max fuzzy brand similarity). Verified by `homograph_probe.py` — **14/14**.
**⚠️ Limit:** "My confusables map covers common Cyrillic/Greek look-alikes, not every Unicode confusable — catches realistic attacks, not an exhaustive adversarial set."

---

## PART 5 — ML concepts from basics (the full glossary)

**Setup:** *Machine learning* — learn patterns from examples, not hand-coded rules. *Supervised* — examples carry labels. *Unsupervised* — no labels, find structure. *Classification* — predict a category; *regression* — predict a number. *Binary classification* — two classes. *Label/ground truth* — the known answer.

**Representation:** *Feature* — one number describing the input. *Feature engineering* — designing those numbers. *Feature vector* — the full list for one example. *TF-IDF* — Term Frequency × Inverse Document Frequency, text → numbers. *n-gram* — a run of n consecutive items (I use char 3–5-grams). *Standardization* (`StandardScaler`) — rescale to mean 0 / variance 1. *Shannon entropy* — randomness of a string.

**Training & evaluation:** *Training/validation(calibration)/test sets* — disjoint slices. *GroupShuffleSplit* — split keeping a group key (domain) on one side. *Cross-validation* — rotate the held-out slice. *Overfitting* — memorizes train, fails on new data. *Underfitting* — too simple to capture the pattern. *Bias–variance trade-off* — too simple = high bias; too complex = high variance. *Data leakage* — test info leaks into training, inflating the score. *Class imbalance* — one class dominates; balance to force real learning. *Determinism* — same inputs → same model (`random_state=42`, `n_jobs=1`).

**Model internals:** *Parameters* — learned (tree splits). *Hyperparameters* — set by you (`n_estimators`, `max_depth`, `learning_rate`). *Decision tree / ensemble / bagging / boosting / gradient boosting / regularization / learning rate / loss function (logloss)* — see Part 9.

**Outputs & metrics:** *Probability output* — `predict_proba`. *Decision threshold* — the cutoff (0.60). *Calibration* — make the probability honest. *Confusion matrix* — TP/FP/TN/FN. *Precision* = TP/(TP+FP). *Recall* = TP/(TP+FN). *False-positive rate* = FP/(FP+TN) — my gated metric. *F1* — harmonic mean of precision & recall. *Accuracy* — fraction correct. *Precision/recall trade-off* — the threshold is the knob. *ROC/AUC* — threshold-independent separation quality.

---

## PART 6 — The dataset, in full

**🟢 Say:** "~1.5M labelled URLs, balanced 50/50 phishing vs legitimate."
**Sources:** PhishTank + OpenPhish (phishing feeds), Kaggle phishing set, Tranco top-sites list (legitimate), plus a generated adversarial set (look-alikes, `@`-tricks, homographs) boosted ×2, and an optional fresh-phishing harvest for a cross-source test.
**🔵 Why only these:** they're the standard, reputable, labelled public sources; mixing feeds reduces single-source bias; Tranco gives a clean legit baseline. **Balanced 50/50** so the model can't score high by always guessing legit. **Capped `MAX_PER_CLASS = 150_000`** per class before augmentation (~300k/class after) to keep training fast and balanced.
**⚠️ Limit:** "It inherits the feeds' biases and is a snapshot in time — phishing distributions drift, so a deployed model needs periodic retraining."

---

## PART 7 — The 22 engineered features, in full

`features.py :: extract_features(url)` → 22 numbers, wrapped `except Exception: return [0]*22` so a malformed URL never crashes the server.

| # | Feature | Phishing signal |
|---|---|---|
| 0 | length / 100 | phishing URLs run long |
| 1 | number of dots | stacked subdomains |
| 2 | number of hyphens | `secure-paypal-login` |
| 3 | number of slashes | deep paths |
| 4 | digit count | `paypa1`, random hosts |
| 5 | Shannon entropy | random-looking hosts |
| 6 | keyword count | login/verify/secure/account |
| 7 | max brand similarity / 100 | fuzzy match to brands |
| 8 | brand-spoof flag | looks like a brand, isn't it |
| 9 | brand-spoof AND keyword | spoof + "login" together |
| 10 | IP-in-URL (regex) | raw IP instead of a name |
| 11 | `@` in authority | the `@`-redirect trick |
| 12 | `@` + dotted host | stronger `@`-trick signal |
| 13 | path depth | many path segments |
| 14 | hyphen in domain | look-alike domains |
| 15 | subdomain depth | `a.b.c.d.evil.com` |
| 16 | suspicious TLD | `.tk .zip .xyz` … |
| 17 | localhost / 127.0.0.1 | local-trick |
| 18 | host keyword tokens | brand words in the host |
| 19 | hyphens in host | `paypal-secure-login` |
| 20 | `xn--` punycode | homograph attack |
| 21 | non-ASCII host after IDN decode | homograph attack |

**Pick 6–8 to name out loud:** length, dots, entropy, brand-similarity, the `@`-trick (11), suspicious-TLD (16), punycode (20). **If asked "which matter most?":** the brand-spoof + corroboration features (8/9) and the structural ones (10/11/16/20/21) — several are decisive enough to trigger the structural override before the model even scores.

---

## PART 8 — TF-IDF from basics

🔵 **"What is TF-IDF and why char n-grams?"**
- **Term Frequency (TF)** — how often a term appears in this document (URL).
- **Inverse Document Frequency (IDF)** — down-weights terms common across *all* documents, up-weights distinctive ones.
- **TF-IDF = TF × IDF** — turns text into a numeric vector emphasizing distinctive substrings.
- **Character n-grams (3–5):** I slide a 3-to-5-character window over the URL (`pay`, `aypa`, `aypal`). This catches look-alike spellings (`paypa1`, `g00gle`) that a word-level model would miss, because the misspelling shares character chunks with the real brand.
**💻 Code (`train_ml_strong.py`):**
```python
char_vec = TfidfVectorizer(max_features=3000, analyzer="char", ngram_range=(3, 5))
word_vec = TfidfVectorizer(max_features=1000)
```
**Say:** "3000 char dims + 1000 word dims, but both weighted only 0.05 vs 15 for the numeric block — TF-IDF is a *secondary* signal." ⚠️ "Fit on the training slice only, or the vocabulary leaks test information."

---

## PART 9 — XGBoost from a single tree up

🔵 **The full "what is XGBoost" build:**
1. **Decision tree** — a flowchart of yes/no feature tests ending in a prediction. Alone: weak, unstable, over/underfits.
2. **Ensemble** — combine many models so errors cancel.
3. **Bagging** (→ Random Forest) — train many trees *independently* on random subsets, average them. Reduces variance.
4. **Boosting** — train trees *sequentially*; each focuses on what the previous ones got wrong. Reduces bias *and* variance.
5. **Gradient boosting** — each new tree is fit to the gradient (steepest-error direction) of the loss function.
6. **XGBoost ("Extreme Gradient Boosting")** — gradient boosting + L1/L2 **regularization** (penalizes complexity → fights overfitting) + fast, parallel, CPU-friendly tree building.

**Why it fits *this* problem:** my input is ~4,000 sparse TF-IDF dims + 22 numeric features with strong **non-linear interactions** ("looks like a brand AND has a suspicious TLD"). Trees capture interactions automatically; `max_depth=7` is exactly that interaction budget. Why not alternatives → Part 19's "why not X" bank.
**⚠️ Limit:** "Boosting can overfit if you over-train; I counter with a low learning rate (0.05) and moderate depth, and I validate on a domain-grouped hold-out."

---

## PART 10 — Calibration from basics

🔵 **"What does 'calibrated' mean?"**
- Raw classifier scores aren't true probabilities — a raw "0.9" doesn't mean "90% likely."
- **Calibration** remaps scores so that among all URLs scored ~0.7, about 70% really are phishing.
- **Isotonic** calibration = fit a non-decreasing step function from raw score → true probability.
- **Why I need it:** my decision logic uses probability thresholds (0.60 to flag, 0.35 for the confident-safe fast path). Those numbers are only meaningful if the probability is honest.
**💻 Code:**
```python
model = CalibratedClassifierCV(base_model, cv="prefit", method="isotonic")
model.fit(X_cal, y_cal)   # cv="prefit": base model already trained; learn the mapping on a DISJOINT slice
```
**⚠️ Limit:** "Isotonic needs a decent calibration set or it overfits the mapping; the simpler sigmoid (Platt) method is more robust on small sets — a conscious trade-off."

---

## PART 11 — The training pipeline (9 steps, with code)

`train_ml_strong.py`, in order:
```
1. LOAD     final_dataset.csv + adversarial_phishing.csv (×2) + legit_urls.csv (+ fresh_phishing.csv)
2. CLEAN    drop label noise — phishing rows sitting on trusted roots
3. BALANCE  50/50, cap MAX_PER_CLASS = 150_000 per class
4. AUGMENT  emit each URL bare + pathed from a SHARED path pool for BOTH classes
            → de-correlates the "has a path ⇒ phishing" artifact
5. STRIP    remove http:// , https://  (scheme must not be a cheat signal)
6. SPLIT    GroupShuffleSplit by registrable domain → disjoint train / calibrate / test
            assert train/cal/test are isdisjoint
7. FIT      char-TFIDF + word-TFIDF + StandardScaler on the TRAIN slice ONLY, then transform the rest
8. TRAIN    base_model.fit(X_train) ; CalibratedClassifierCV(...).fit(X_cal)  (disjoint)
9. SAVE     model.pkl + char_vectorizer.pkl + word_vectorizer.pkl + scaler.pkl  (all four travel together)
```
**Say it in one breath:** "Assemble the feeds, clean label noise, balance 50/50, augment to kill the path artifact, split by domain so nothing leaks, fit transforms on train only, train the trees, calibrate on a disjoint slice, save. Deterministic and gated on not regressing the false-positive ceiling."
**💻 Why `n_jobs=1` + `random_state=42`:** XGBoost's parallel histogram build is otherwise order-nondeterministic; serial + fixed seed makes a retrain bit-for-bit reproducible, which is what makes the golden-score regression tests meaningful.

---

## PART 12 — Data leakage (your strongest story)

🔵 **Lead with this unprompted — it's what makes you sound senior.**
- **Data leakage** = information from the test set secretly influences training, so your score is inflated and collapses in the real world.
- **Leak 1 — domain leakage:** a plain row-split put the same domain in train *and* test, so the model learned "I've seen this domain," not "this is phishing." **Fix:** `GroupShuffleSplit` keyed on the registrable domain — a domain is wholly in train or wholly in test, never both.
- **Leak 2 — path artifact:** almost every phishing sample had a URL path and legit ones didn't, so the model learned "has a path ⇒ phishing." **Fix:** path-decorrelation augmentation — emit every URL both bare and pathed, drawing paths from the *same* pool for both classes.
- **Result:** the first model's **~98%** was leakage-inflated. The honest, domain-grouped number is **~74%**.

**The hook (say verbatim):** "The thing I'm proudest of isn't a high number — it's that I caught my *own* 98% being a lie, diagnosed two leaks, fixed the evaluation, and reported an honest 74%."

---

## PART 13 — The 6-gate serving pipeline (with code)

`main.py`, model-first ladder:
```
Gate 1  ML model          pred, prob, reason = await asyncio.to_thread(predict_ml, url)
Gate 2  Structural CRIT    raw-IP host / @-authority / corroborated brand-spoof → PHISHING 10.0
Gate 2b Blocklist EXACT    known-bad URL → PHISHING 9.0  (shared-host carve-out overrides allowlist)
Gate 2c Allowlist          trusted registrable root → SAFE ("Globally trusted domain")
Gate 3  Confident-safe     pred==0 AND prob < 0.35 AND no typo/subdomain/brand flag → SAFE (fast path)
Gate 4  Heuristics+dampener brand/typo/subdomain/IP/keyword/domain-age/SSL, then if prob < DAMPENER → score*0.5
                            → SUSPICIOUS (≥ T_SUSPICIOUS) or PHISHING (≥ T_PHISHING)
```
**💻 Inside Gate 1 (`predict_ml_only.py`):**
```python
if host_is_loopback(host): return (0, 0.001, ...)          # localhost guard
if host in TRUSTED_ROOTS:  return (0, 0.001, "Globally trusted domain")
brand_spoof_corroborated = feats[8] and (feats[9] or feats[16] or feats[20] or feats[21])
if host_is_ip(host) or feats[11] or brand_spoof_corroborated:
    return (1, 0.999, "Critical: Structural security risk detected")  # structural override
X = stack_features(x_char, x_word, x_num)                   # same weights as training
prob = model.predict_proba(X)[0][1]
pred = int(prob > ML_DECISION_THRESHOLD)                    # 0.60 serving
```
**Why this order:** certainties first where they're cheap (loopback, allowlist), structural red flags that no legit site has (raw IP, `@`-authority), then the exact-match blocklist, then the fast path for confident-safe, then the full heuristic scorer with a dampener that halves borderline scores the model already thinks are safe.

---

## PART 14 — Homograph detection (with code)

🔵 **From basics:**
- **IDN / punycode:** internationalized domains are ASCII-encoded as `xn--…`. `xn--pypal-4ve.com` *displays* as "pаypal" with a Cyrillic а — visually identical, a different domain.
- **Confusable folding / skeleton:** normalize look-alike Unicode (Cyrillic/Greek) to ASCII via Unicode NFKD + a `_CONFUSABLES` map, collapsing the disguise to its true look-alike skeleton.
- **Fuzzy matching:** `rapidfuzz` scores string similarity so the skeleton `paypal` (folded from pаypal) matches the real brand.
**💻 Code (`features.py`):**
```python
_decode_idn(host)   # xn--…  → real unicode host
_skeleton(s)        # NFKD + _CONFUSABLES fold → plain-ASCII look-alike
# feature 20: 'xn--' present ;  feature 21: non-ASCII host after decode ;  feature 7: max fuzzy brand similarity
```
Feeds the structural override in Gate 1 (feats[20]/[21] corroborate a brand-spoof). Verified: `homograph_probe.py` → **14/14** caught.
**⚠️ Limit:** "Covers common Cyrillic/Greek confusables, not every Unicode confusable — realistic attacks, not an exhaustive adversarial set."

---

## PART 15 — End-to-end walkthrough (3 traced URLs)

**The money question: "walk me through what happens for a URL."**

**A) `https://www.google.com`**
1. Normalize → `https://www.google.com`. 2. `parse_host` → `google.com`. 3. Gate 1: `google.com` ∈ `TRUSTED_ROOTS` → returns `(0, 0.001, "Globally trusted domain")` — **model never runs**. 4. Verdict **SAFE**, score ~0. 5. Logged to SQLite.

**B) `http://192.168.0.5/login.php`**
1. Normalize. 2. `parse_host` → `192.168.0.5`. 3. Gate 1: `host_is_ip` is true → structural override `(1, 0.999, "Critical: Structural security risk detected")`. 4. Gate 2 confirms → **PHISHING**, score 10.0. 5. Logged. (The model's opinion is irrelevant — a raw-IP login host is a certainty.)

**C) `http://secure-paypa1-login.tk/verify`**
1. Normalize. 2. `parse_host` → `secure-paypa1-login.tk`. 3. Gate 1: not loopback, not trusted. Features fire — brand-spoof (7/8, `paypa1`≈paypal), keyword (6, "login/verify"), suspicious TLD (16, `.tk`). `brand_spoof_corroborated` true → structural override `(1, 0.999, …)`. 4. **PHISHING**, score 10.0, reasons list the brand-spoof + TLD. 5. Logged. (If it *hadn't* tripped the override, it would fall to the calibrated model, then Gate 4 heuristics.)

**Say:** "Two of those never touch the model — that's the point of the hybrid design: certainties handled by rules, ambiguity handled by the model."

---

## PART 16 — The honest numbers (every metric)

| Metric | Value | How measured | Say |
|---|---|---|---|
| Grouped hold-out accuracy | **~74%** | leakage-free, domain-grouped test | "honest generalization to unseen domains" |
| **False-positive rate** | **6.23%** | `fp_sweep.py`, 80,110 legit URLs, model-only | "the metric I gate on" |
| Cross-source recall | **~70.4%** | `cross_source_recall_probe.py`, OpenPhish, novel roots, at 0.60 | "caught on a feed never trained on" |
| Equal-FP recall | **~61%** | `operating_point.py`, versions compared at equal FP | "why 'it improved' is verifiable" |
| Homograph probe | **14/14** | `homograph_probe.py` | look-alike spoofs |
| pytest | **128 passing** | `tests/` | regression safety net |
| Retrains | **v3.0 → v3.5**, FP **10.4% → 6.23%** | gated ≤ 9.70% FP ceiling | "five gated retrains, revert on regression" |
| Retired, inflated | ~98% | old leaky row-split | **never claim — that was the lie** |

**"Why only 74%?"** → "Because it's honest — the 98% was data leakage. In security the costly error is a false positive, so I gate on FP rate (6.23%), not accuracy. Accuracy treats a missed phish and a false alarm as equally bad; they aren't."

---

## PART 17 — Testing & deployment

**Testing:** 128 pytest tests — feature-extraction correctness, the feature-weight contract (value + a train/serve golden score so a silent drift fails CI), host-parsing security (parse-host not substring), CSV-injection guard, and the probe scripts (`fp_sweep`, `cross_source_recall_probe`, `homograph_probe`, `operating_point`). **Determinism** (`random_state=42`, `n_jobs=1`) is what makes golden-score tests meaningful.
**Deployment:** Render (FastAPI backend, blueprint `render.yaml`, Python 3.12.1, `uvicorn --host 0.0.0.0 --port $PORT`, health check `/health`) + Vercel (static frontend, `vercel.json`) + a single deploy override `frontend/js/env.js` (`window.PHISHGUARD_API_BASE`). Model artifacts committed so a fresh clone runs; `phishtank.csv` gitignored but `main.py` degrades gracefully. ⚠️ "Deployed ≠ has users — it's a working deployment, not a product with traffic."

---

## PART 18 — Full tech stack

| Layer | Tech | Headline or mention |
|---|---|---|
| Language | Python 3.12 | 🟢 header |
| Model | XGBoost 2.0.3 | 🟢 |
| ML tooling | scikit-learn (TF-IDF, StandardScaler, CalibratedClassifierCV), numpy/scipy/pandas | 🔵 |
| Fuzzy match | rapidfuzz | 🔵 (homograph) |
| Domain meta | python-whois, ssl | ⚪ |
| Backend | FastAPI, uvicorn, pydantic | 🟢 |
| DB | SQLite | 🟢 |
| Frontend | vanilla HTML/CSS/JS | ⚪ |
| Extension | Chrome Manifest V3 | 🟢 |
| Analytics | Power BI CSV export | ⚪ |
| Deploy | Render + Vercel | ⚪ (be honest) |
| Tests | pytest (128) | ⚪ |

---

## PART 19 — THE QUESTION BANK (every question that can arise)

### A. Machine learning fundamentals
- **Supervised or unsupervised?** → Supervised binary classification; I had labels. (Part 2.1)
- **Classification or regression?** → Classification — a category, not a number.
- **Binary or multi-class?** → Binary (P(phishing)); SAFE/SUSPICIOUS/PHISHING is post-processing banding, not three learned classes.
- **What's a feature / feature vector?** → Part 5.
- **What's overfitting? how did you prevent it?** → memorizing train; prevented by grouped split, low learning rate, moderate depth, regularization, calibration on a disjoint slice.
- **Bias vs variance?** → too-simple = high bias (underfit); too-complex = high variance (overfit); XGBoost depth/LR balance them.
- **Parameters vs hyperparameters?** → learned (tree splits) vs set-by-you (`n_estimators`, `max_depth`, `learning_rate`).

### B. The model
- **What is XGBoost?** → tree → ensemble → boosting → gradient boosting → regularized. (Part 9)
- **Boosting vs bagging?** → bagging trains trees independently and averages (Random Forest); boosting trains sequentially, each correcting the last.
- **Explain your hyperparameters.** → Part 2.2, each one + why.
- **What's the loss function?** → logloss (cross-entropy), the right loss for probabilistic binary classification.
- **What does 'calibrated' mean / why?** → Part 10.
- **Isotonic vs sigmoid calibration?** → isotonic = flexible non-decreasing step fn (needs more data); sigmoid/Platt = simpler, robust on small sets. I used isotonic; set is large enough.
- **Is it one model or two?** → one base XGBoost + a calibration wrapper, trained on disjoint slices.

### C. Why XGBoost, not X (the comparison bank)
- **vs Logistic Regression?** → linear, can't capture interactions without hand-made cross-features; underfits.
- **vs Naive Bayes?** → assumes feature independence (false here — length/dots/subdomains correlate).
- **vs a single Decision Tree?** → weak/unstable; over- or under-fits. Boosting exists to fix this.
- **vs Random Forest?** → good, but bagging averages independent trees; boosting corrects systematic errors and usually edges it on structured + sparse data at similar cost.
- **vs SVM?** → scales badly to 1.5M rows (≈quadratic), slow, no natural calibrated probabilities.
- **vs k-NN?** → lazy (slow at inference), curse of dimensionality on ~4,000 sparse dims.
- **vs a neural net / MLP?** → overkill for tabular; trees match or beat MLPs there with less data, no GPU, less tuning, more explainability.
- **vs char-CNN / LSTM / Transformer on raw URL text?** → a legit research direction, but heavier (GPU, more data, slower, bigger deploy) for marginal gains. Honest meta-point: "Model choice follows constraints — CPU, tabular+sparse, explainable, gated. Change the constraints and I'd revisit a neural model."

### D. Data & features
- **What dataset, how much, why only these?** → Part 6.
- **How did you label the data?** → labels come from the feeds themselves (PhishTank/OpenPhish = phishing; Tranco = legit); I cleaned label noise (phishing rows on trusted roots).
- **Class imbalance — how handled?** → balanced 50/50; `scale_pos_weight=1` because already balanced.
- **Name your features / which matter most?** → Part 7.
- **What's TF-IDF / why char n-grams?** → Part 8.
- **Why StandardScaler?** → so a big-magnitude numeric feature doesn't drown a small one; fit on train only.

### E. Evaluation & honesty
- **What's your accuracy?** → ~74% honest + the leakage story + "I gate on FP rate." (Part 16)
- **Precision vs recall — which do you optimize?** → minimize false positives (6.23% gated); recall ~70%, backed by the blocklist.
- **What's a false positive here and why does it matter?** → flagging a real site as phishing; destroys user trust instantly — the costly error in security.
- **How did you validate honestly?** → domain-grouped split, disjoint 3-way, transforms fit on train only. (Parts 11–12)
- **What is data leakage? did you have any?** → yes, two leaks, both fixed. (Part 12 — your hook.)
- **How do you know it improved?** → compared versions at *equal* false-positive rate across five gated retrains; FP 10.4%→6.23%.

### F. The hybrid pipeline / system design
- **Why rules AND a model?** → Part 4.1 — certainties as rules, ambiguity to the model.
- **What runs first?** → the model (Gate 1), then the rule gates. (Part 13)
- **Isn't the allowlist cheating?** → it's a safety net; model measured without it. (Part 4.3)
- **Why exact-match blocklist, not domain?** → avoids condemning a whole shared host. (Part 4.2)
- **How does a request flow end-to-end?** → Part 15.
- **How is it real-time / how fast?** → sub-second per URL; slow WHOIS/SSL cached + off the event loop. (Part 3.4)
- **Why FastAPI not Flask?** → async, Pydantic validation, auto docs. (Part 3.1)

### G. Security
- **How do you prevent SQL injection?** → parameterized queries. (Part 3.2)
- **The `@`-trick — what is it?** → `good.com@evil.com` routes to evil.com; feature 11 flags `@` in the authority.
- **What MV3 security issues did you hit?** → the CSP `new Function` ban and the `innerHTML` DOM-XSS, both fixed. (Part 3.3)
- **CSV injection?** → `csv_safe` prefixes `= + - @` cells with a quote so spreadsheets don't execute them.
- **Could someone bypass it?** → yes — a clean brand-new URL (no page content analysis); honest scope limit, mitigated by the live blocklist.

### H. Deployment & engineering
- **Is it live / does it have users?** → working deployment on Render + Vercel; not a product with traffic. Be honest. (Part 17)
- **How did you test it?** → 128 pytest + probe scripts + golden-score determinism. (Part 17)
- **How would you scale it?** → multiple uvicorn workers, Postgres instead of SQLite, a live blocklist API, rate-limiting, a model registry + periodic retrain.
- **How do you retrain / update?** → `train_ml_strong.py`, gated on the ≤9.70% FP ceiling, back up the model first, golden-score tests must pass.

### I. Project / behavioral
- **What was the hardest part?** → catching my own 98% as leakage and rebuilding the evaluation honestly.
- **What are you proudest of?** → the honesty story — auditing my own metric. (Part 1)
- **What would you do differently / next?** → learned feature-block weights; page-content features; a live blocklist API; a char-level neural experiment with a GPU budget; hyperparameter search.
- **What did you learn?** → that an impressive number is worthless if the evaluation is wrong; and the MV3 security model first-hand.
- **Why did you build it?** → phishing is the #1 initial-access vector; I wanted a real, explainable ML security tool end-to-end.

### J. Curveballs
- **"Your 74% is low."** → "It's honest — the 98% was leakage. Operationally the system is stronger because it also uses the blocklist and allowlist, and I gate on a 6.23% false-positive rate."
- **"Why not just use Google Safe Browsing?"** → "That's a blocklist — great for *known* bad URLs, which is exactly why I include one. The ML model adds generalization to *unseen* look-alike patterns a blocklist hasn't seen yet."
- **"What if TF-IDF is doing all the work?"** → "It isn't — it's weighted 0.05 vs 15 for the numeric block, and the structural overrides fire before the model on the decisive cases. TF-IDF is a secondary spelling signal."
- **"Prove it's not memorizing."** → "The domain-grouped split guarantees test domains were never in training, and the cross-source recall probe runs on a feed and roots the model never saw."

---

## PART 20 — Honesty rules / traps

1. **Never say 98%.** Say ~74% + the leakage story. The 98% is the lie you *caught* — it's your best moment, not your number.
2. **TF-IDF is secondary** (0.05 vs 15). Don't let an interviewer bait you into overselling it.
3. **The extension is "built," not "deployed to users"** — loaded unpacked, not on the Web Store.
4. **"Deployed" ≠ "has users"** — it's a working deployment.
5. **The allowlist is a safety net, not the classifier** — and you measure the model without it.
6. **The blocklist is a snapshot, not a live API.**
7. **URL-string only** — no page content; say so before they trap you.
8. **Hyperparameters are hand-tuned, not grid-searched.**
9. **If you don't know, say "I'd check the code"** — never invent a number.

---

## PART 21 — Rapid-fire flashcards

- *Model?* → calibrated XGBoost, supervised binary classification.
- *Trained on?* → ~1.5M labelled URLs, 50/50, split by domain.
- *Features?* → 22 engineered numeric + char TF-IDF (3000, 3–5 grams) + word TF-IDF (1000).
- *Feature weights?* → (0.05, 0.05, 15) = (char, word, numeric).
- *Key hyperparameters?* → 400 trees, depth 7, LR 0.05, seed 42, n_jobs 1.
- *Decision threshold?* → 0.60 flag, 0.35 confident-safe fast path.
- *Accuracy?* → ~74% honest (not 98% — that was leakage).
- *False-positive rate?* → 6.23% on 80,110 legit URLs (gated ≤ 9.70%).
- *Recall?* → ~70% cross-source.
- *Homograph?* → 14/14.
- *Tests?* → 128 pytest.
- *Why XGBoost?* → non-linear interactions on tabular+sparse, CPU-fast, regularized, explainable.
- *Why calibrated?* → thresholds are probabilities; a "0.7" must mean ~70%.
- *Leakage?* → domain leakage (→ GroupShuffleSplit) + path artifact (→ augmentation).
- *Hybrid gates?* → ML → structural → blocklist → allowlist → confident-safe → heuristics+dampener.
- *Backend?* → FastAPI, async, model off the loop via asyncio.to_thread.
- *DB?* → SQLite, parameterized, auto-init.
- *Extension?* → Chrome MV3, service worker + content-script banner; fixed CSP + XSS bugs.
- *Proudest of?* → catching my own 98% as a lie.

*End of bible. Everything here maps to a file, a number, or a reproducible test.*
