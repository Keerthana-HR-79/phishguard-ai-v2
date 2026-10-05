# PhishGuard AI — Interview Master Guide
*One document, everything you need to explain and defend the project end-to-end. Verified against the actual source code (backend v3.2.0, model v3.5, 128 pytest passing).*

---

## How to use this guide

Every concept is tagged so you know how hard to study it:

| Tag | Meaning |
|-----|---------|
| 🟢 **ON RESUME** | A word/claim that is literally in your 3 bullets. You **must** defend it word-for-word. |
| 🔵 **LEARN DEEP** | Not on the resume, but the near-certain *follow-up* the moment you say a resume word. Study it hard. |
| ⚪ **BACKGROUND** | Not on the resume, unlikely to be pressed. Know it exists; mention only if it comes up. |

**Golden rule of the whole project:** *Everything you say must map to a file, a number, or a reproducible test.* If you can't back it, don't say it.

---

## Table of contents

1. [Your resume block (the exact words)](#1-your-resume-block)
2. [Resume → defense map (what to study)](#2-resume--defense-map)
3. [The 60-second pitch](#3-the-60-second-pitch)
4. [What the project is + the 3 surfaces](#4-what-the-project-is)
5. [Supervised vs unsupervised (from basics)](#5-supervised-vs-unsupervised)
6. [The dataset — what, how much, and why only these](#6-the-dataset)
7. [Feature engineering — the 22 features (from basics)](#7-feature-engineering)
8. [TF-IDF — char & word (from basics)](#8-tf-idf)
9. [XGBoost — from a single tree up (from basics)](#9-xgboost-from-basics)
10. [Calibration — why "0.7" must mean 70% (from basics)](#10-calibration)
11. [How the model is trained — the 9 steps](#11-how-the-model-is-trained)
12. [Data leakage — your strongest story (from basics)](#12-data-leakage)
13. [Accuracy & the honest numbers](#13-accuracy--the-honest-numbers)
14. [The 6-gate detection pipeline (bullet 3)](#14-the-6-gate-pipeline)
15. [Homograph detection (bullet 3)](#15-homograph-detection)
16. [FastAPI backend + SQLite logging (bullet 2)](#16-fastapi-backend--sqlite)
17. [Chrome extension, MV3 (bullet 2)](#17-chrome-extension)
18. [END-TO-END WALKTHROUGH — the money question](#18-end-to-end-walkthrough)
19. [Testing & deployment](#19-testing--deployment)
20. [Full tech stack — headline vs mention](#20-full-tech-stack)
21. [Mock interview Q&A](#21-mock-interview-qa)
22. [Honesty rules (protect yourself)](#22-honesty-rules)

---

## 1. Your resume block

**Header:**
> **PhishGuard AI — Phishing Detection System** | *Python, Machine Learning, FastAPI, XGBoost, Chrome Extension*

**Bullets:**
> - Developed an end-to-end phishing URL detection system using a **machine learning** model (**XGBoost**) **trained** on engineered URL features.
> - Built a **FastAPI** backend with **SQLite** event logging and a **Chrome (Manifest V3)** extension for real-time URL scanning and in-page phishing warnings.
> - Designed a hybrid detection pipeline combining the ML model with a **blocklist**, a trusted-domain **allowlist**, and **homograph detection** for look-alike domains.

Everything below exists to let you defend every bolded word and survive the follow-ups.

---

## 2. Resume → defense map

This is the single most useful table in the guide — it tells you **exactly what to study** and how deep.

| Keyword / claim | Tag | Where it lives in the code | What they'll ask next |
|---|---|---|---|
| end-to-end system | 🟢 | whole repo | "Walk me through it" → §18 |
| machine learning | 🟢 | `train_ml_strong.py` | "Supervised or unsupervised?" → §5 |
| XGBoost | 🟢 | `train_ml_strong.py:287` | "What is XGBoost / why it?" → §9 |
| trained | 🟢 | `train_ml_strong.py` | "On what data? how?" → §6, §11 |
| engineered URL features | 🟢 | `features.py` | "Name some features" → §7 |
| FastAPI | 🟢 | `main.py` | "Why FastAPI not Flask?" → §16 |
| SQLite event logging | 🟢 | `database.py` | "What do you log?" → §16 |
| Chrome (Manifest V3) | 🟢 | `extension/manifest.json` | "What's MV3 / is it published?" → §17 |
| real-time scanning | 🟢 | `main.py` `/predict_url` | "How fast / how?" → §18 |
| hybrid pipeline | 🟢 | `main.py` 6 gates | "Why rules AND a model?" → §14 |
| blocklist | 🟢 | `main.py:176-217` | "Why exact-match not root?" → §14 |
| trusted-domain allowlist | 🟢 | `predict_ml_only.py:60`, `config.py:29` | "Isn't allowlisting cheating?" → §14 |
| homograph detection | 🟢 | `features.py:34-65` | "How does it work?" → §15 |
| TF-IDF (char + word) | 🔵 | `train_ml_strong.py:254-255` | "What is TF-IDF / why char n-grams?" → §8 |
| calibration | 🔵 | `train_ml_strong.py:305` | "What does calibrated mean?" → §10 |
| data leakage / GroupShuffleSplit | 🔵 | `train_ml_strong.py:238-250` | "How did you validate honestly?" → §12 |
| accuracy ~74% / FP 6.23% | 🔵 | `fp_sweep.py`, `MODEL_AUDIT.md` | "What's your accuracy?" → §13 |
| the 22 features (specific list) | 🔵 | `features.py:98-165` | "Why 22? which matter?" → §7 |
| the 6 gates (specific order) | 🔵 | `main.py:350-499` | "What runs first?" → §14, §18 |
| Python | 🟢(header) | everywhere | version? 3.12 |
| scikit-learn | ⚪ | training | the TF-IDF/scaler/calibration lib |
| Power BI export | ⚪ | `export_to_bi.py` | analytics layer, mention only |
| Render + Vercel deploy | ⚪ | `render.yaml`, `vercel.json` | "Is it live?" → §19 (be honest) |
| pytest (128 tests) | ⚪ | `tests/` | "How did you test?" → §19 |

**Study order:** master all 🟢 first (you can't put a word on a resume you can't defend), then all 🔵 (these *will* come up), then skim ⚪.

---

## 3. The 60-second pitch

> "PhishGuard AI is a real-time phishing-**URL** detector. You give it a URL and it returns a verdict — SAFE, SUSPICIOUS, or PHISHING — with a 0–10 risk score and the exact reasons.
>
> The core is a **machine-learning model** — a calibrated XGBoost classifier **trained** on about 1.5 million labelled URLs using features I engineered from the URL string. But a URL-string model alone can't know a specific site is on a live blacklist, and it should never flag google.com, so I wrapped it in a small **rule pipeline**: the model scores first, then gates handle the certainties — a known-bad blocklist, a trusted-domain allowlist, and structural red flags like raw-IP hosts or look-alike (homograph) domains.
>
> It's exposed three ways: a **FastAPI** backend that holds the model, a web dashboard, and a **Chrome Manifest-V3 extension** that checks pages in the background. Scan history is logged to **SQLite**.
>
> The part I'm proudest of isn't a high accuracy number — it's that I caught my *own* accuracy number being a lie. My first model reported ~98%, I audited it, found data leakage, fixed the evaluation, and reported an honest ~74%."

That last paragraph is your hook. Interviewers remember it. (Details in §12.)

---

## 4. What the project is

**One sentence:** a supervised ML system that classifies a URL as phishing or legitimate in real time, wrapped in a rule ladder that handles the cases a URL-only model provably can't.

**Three surfaces, one brain:**
1. **Web app** — URL checker + analytics dashboard (vanilla HTML/CSS/JS). ⚪
2. **Chrome extension (MV3)** — checks every page you visit in the background. 🟢
3. **FastAPI backend** — holds the model + rules; both of the above call it. 🟢

**Scope boundary you must state honestly:** it analyzes the **URL string only**. It does *not* read page content, follow redirects, or render JavaScript. That's a deliberate scope choice (fast, no browser sandbox needed) and the honest answer to "could it be fooled by X on the page" is *"yes — page-content analysis is documented future work."*

---

## 5. Supervised vs unsupervised

🟢 **This is the first follow-up after "machine learning." Nail it.**

**From basics:**
- **Supervised learning** = you train on examples that already have the *right answer* (a label). The model learns to map inputs → known labels. Two kinds: *classification* (predict a category) and *regression* (predict a number).
- **Unsupervised learning** = no labels; the model finds structure on its own (clustering, anomaly detection).

**What PhishGuard uses:** **supervised, binary classification.**
- Every training URL carries a label: `phishing` or `legitimate` (the dataset column is literally `url,type`).
- The target is one of two classes → **binary**.
- The model outputs a probability 0–1 that the URL is phishing.

**Why supervised and not unsupervised?**
> "I had abundant *labelled* data — public feeds of confirmed phishing URLs and ranked legitimate domains — and a crisp target (phishing vs not). That's the textbook case for supervised classification. Unsupervised anomaly detection would make sense if I had no labels or was hunting unknown attack *types*, but here the signal is well-defined and labelled, so supervised learning is both simpler and far more accurate."

**"Why XGBoost specifically and not logistic regression or a neural net?"** → see §9.

---

## 6. The dataset

🟢 "trained on …" and ⚪ the exact counts. Know the shape; the exact numbers are 🔵.

### What's in it

The training set is assembled from several **public** feeds (columns `url,type`):

| File | Rows | What it is |
|---|---|---|
| `final_dataset.csv` | ~1,508,510 | the base mix (~1,345,737 legit + ~162,313 phishing) |
| `fresh_phishing.csv` | ~154,798 | freshly-harvested, currently-active phishing roots |
| `legit_urls.csv` | ~80,111 | curated legitimate URLs (also the FP-sweep test set) |
| `adversarial_phishing.csv` | ~11,930 | synthesized brand/keyword spoofs (e.g. `paypa1-login.tk`) |
| `fresh_holdout.csv` | ~5,001 | unseen phishing domains, *never* trained on (for honest recall) |

**Raw sources** these are built from:
- **Tranco** (top 1M legitimate domains) — a research-grade ranking.
- **OpenPhish** + **PhishTank** — live, community-verified phishing feeds.
- **Phishing.Database** (ACTIVE list, ~391,986) — large aggregated phishing feed.
- **Kaggle** phishing datasets — supplementary.

After cleaning and balancing, training runs on a **50/50 balanced** blend, capped at **150,000 per class before augmentation**, which **doubles to ~300k/class** after augmentation (§11).

### "Why only these datasets?" 🔵

> "Three reasons. **Quality:** these are the standard, continuously-updated, *labelled* phishing/legit sources in security research — OpenPhish and PhishTank are human-verified, and Tranco is specifically hardened against the manipulation that plagued older rankings like Alexa. **Scale:** together they give ~1.5M labelled URLs across huge domain diversity, which a URL-lexical model needs to generalize. **Availability:** they're public and free; comparable proprietary threat feeds are paid and can't be shipped in a portfolio repo. I also *added* my own two sets — a synthesized adversarial set for brand look-alikes, and a freshly-harvested set of active phishing roots — to cover gaps the public feeds had, like clean bare-domain phishing."

### "Why balance it 50/50?" 🔵

> "Real traffic is mostly legitimate, so the raw feeds are imbalanced. If I trained on that, the model could score 95% just by always guessing 'legit' and never catch anything. Balancing to 50/50 forces it to actually learn the phishing signal. I set `scale_pos_weight=1` in XGBoost precisely because the data is already balanced."

### Data cleaning you did (the "A5" rules) 🔵

Before balancing, two surgical filters remove **label noise** (`train_ml_strong.py:149-190`):
- **(a)** Drop any *phishing* row whose registrable root is on the trusted allowlist (a feed sometimes flags a path on a legit host; that would teach a false positive like `byjus.com/... → phishing`).
- **(b)** Drop **URL shorteners and free-hosting roots** (`bit.ly`, `blogspot.com`, `github.io`, `vercel.app`, …) from *both* classes — one such root is shared by thousands of unrelated sites, so "this root = legit/phishing" is pure noise.
- *(There was a rule (c) — dropping phishing on any root that also appeared in legit — but I measured it, it made false positives **worse** (10.4%→13.8%), so I reverted it. Good thing to mention: it shows you measure, not guess.)*

---

## 7. Feature engineering

🟢 "engineered URL features." 🔵 the specific 22.

**From basics — what is a feature?** A feature is a single measurable number describing the input. ML models eat numbers, not raw strings, so I turn each URL into a fixed vector of numbers that encode known phishing signals.

PhishGuard builds **22 hand-engineered numeric features** per URL (`features.py`), *plus* the TF-IDF text features (§8). The vector is always length 22 — a test locks that so a refactor can't silently reorder them.

### The 22 features (grouped)

**Basic shape (0–5):**
- `0` URL length ÷ 100
- `1` number of dots
- `2` number of hyphens
- `3` number of slashes
- `4` number of digits
- `5` **Shannon entropy** of the URL (random-looking hosts like `x7f3q9.com` score high)

**Keywords (6):**
- `6` count of phishing keywords in the URL (`login`, `verify`, `secure`, `account`, …)

**Brand analysis (7–9)** — *host-only, so a path can't spoof it:*
- `7` max fuzzy similarity to a known brand ÷ 100 (catches `paypa1`, `g00gle`)
- `8` **brand-spoof flag** — looks like a brand but the domain *isn't* that brand
- `9` brand-spoof **AND** a phishing keyword present (corroboration)

**Structure (10–17):**
- `10` raw IP address appears in URL
- `11` **`@` in the authority** (the credential-hiding trick: `http://paypal.com@evil.com`)
- `12` `@` with a dotted host after it
- `13` path depth (number of path segments)
- `14` hyphen in the domain
- `15` subdomain depth
- `16` suspicious TLD (`.tk`, `.zip`, `.xyz`, …)
- `17` localhost / 127.0.0.1 present

**Host-level salad (18–19):**
- `18` exact phishing-keyword tokens in the host (catches `verify-your-bank-account.net`)
- `19` hyphens in the host only

**IDN / homograph (20–21)** — see §15:
- `20` punycode label present (`xn--`)
- `21` non-ASCII character in the host after IDN decode

**Defensive detail worth saying:** the whole extractor is wrapped so that *any* malformed input returns `[0]*22` instead of crashing — "the feature layer can never take the API down."

### "Why 22, and which matter most?" 🔵

> "Each feature encodes a specific signal a URL string can carry — I didn't add features for the sake of count. The highest-signal ones are the structural certainties: `@`-in-authority, raw-IP host, suspicious TLD, and the corroborated brand-spoof flag. The brand-similarity and entropy features catch look-alikes and random-looking hosts. The numeric block as a whole dominates the decision — see the feature weights in §8."

---

## 8. TF-IDF

🔵 On the resume only indirectly (via "engineered features"), but a very likely question once you mention text features. **Know the honest weak spot.**

**From basics:** **TF-IDF = Term Frequency × Inverse Document Frequency.** It converts text into numbers. A term scores high in a document if it appears *often there* (TF) but is *rare across all documents* (IDF) — so distinctive terms get weight, common ones ("http", "www", "com") get damped.

PhishGuard builds **two** TF-IDF representations of the URL (`train_ml_strong.py:254-255`):
- **Character n-grams (3–5)**, 3,000 dims — sequences of 3 to 5 characters. This catches look-alike *spellings* the numeric features miss: `paypa1`, `g00gle`, `amaz0n`. 🔵
- **Word TF-IDF**, 1,000 dims — catches phishing vocabulary patterns.

The protocol (`http://`) is stripped before vectorizing so the model can't cheat on `http` vs `https`.

### ⚠️ The honest weak spot you must own 🔵

The three feature blocks are combined with **fixed weights `(0.05, 0.05, 15)`** = (char-TF-IDF, word-TF-IDF, numeric) (`config.py:86`). So the **numeric block dominates** and TF-IDF is a **secondary signal.**

If pushed — *"does TF-IDF even matter at 0.05?"* — say:
> "It's a deliberately secondary signal; the engineered numeric features carry most of the decision. TF-IDF is there to catch spelling look-alikes the numeric features don't. Letting the model *learn* those block weights instead of me hand-setting them is a documented future improvement."

Do **not** oversell TF-IDF as the core. That's a trap.

**Why the same weights at train and serve?** They're applied through **one shared helper** `config.stack_features` used by *both* `train_ml_strong.py` and `predict_ml_only.py`, so training and serving can never drift — a train/serve weight mismatch is a classic silent accuracy bug, and this makes it impossible.

---

## 9. XGBoost from basics

🟢 On the resume. Expect "what is it" and "why it." Build the answer from the ground up.

**Step 1 — Decision tree.** A flowchart of yes/no questions on features ("is the TLD suspicious? is there an `@`?") ending in a prediction. Simple, but one tree is weak and overfits.

**Step 2 — Ensemble.** Combine many trees so their errors cancel out.

**Step 3 — Boosting.** Build trees **sequentially**, where each new tree focuses on the examples the previous trees got **wrong**. (Contrast: a Random Forest builds trees *independently* in parallel.)

**Step 4 — Gradient boosting.** "Focuses on errors" made precise: each new tree is fit to the **gradient of the loss function** — the direction that most reduces the error. Predictions are the **sum** of all trees' outputs.

**Step 5 — XGBoost = "Extreme Gradient Boosting":** an optimized, **regularized** implementation of gradient boosting. The regularization (penalizing overly complex trees) is what controls overfitting; it's also fast and handles sparse mixed feature spaces well.

**Your hyperparameters** (`train_ml_strong.py:287`) — know these cold:
- `n_estimators=400` — 400 trees.
- `max_depth=7` — each tree asks up to 7 questions deep.
- `learning_rate=0.05` — each tree contributes modestly, so the ensemble is stable.
- `random_state=42`, `n_jobs=1` — **deterministic**: a retrain is bit-for-bit reproducible (XGBoost's parallel build is otherwise order-nondeterministic). This is what makes the "golden score" tests a real lock.
- `scale_pos_weight=1` — because the data is balanced 50/50.

### "Why XGBoost over logistic regression?" 🔵
> "My input is ~4,000 sparse TF-IDF dimensions plus 22 dense numeric features with *non-linear interactions* — e.g. 'looks like a brand AND has a suspicious TLD' is far more dangerous than either alone. Logistic regression is linear; it can't capture those interactions without me manually building cross-features. Tree boosting captures them automatically."

### "Why not a neural network / deep learning?" 🔵
> "For tabular, sparse data at this scale, gradient-boosted trees usually match or beat neural nets while training in seconds on a CPU with no GPU, needing far less tuning, and overfitting less. A neural net is overkill for a URL string and harder to explain in exactly this kind of interview."

---

## 10. Calibration

🔵 Near-certain follow-up because the serving thresholds are probabilities.

**From basics:** a classifier's raw output score isn't automatically a true probability. A raw "0.7" from XGBoost doesn't necessarily mean "70% likely phishing." **Calibration** fixes that — it maps raw scores to honest probabilities.

PhishGuard uses **isotonic calibration** via `CalibratedClassifierCV(base_model, cv="prefit", method="isotonic")` (`train_ml_strong.py:305`). Isotonic regression learns a flexible, monotonic (only-ever-increasing) mapping from raw score → calibrated probability.

**Why it matters here:** the serving logic uses **probability thresholds** — decision at **0.60**, confident-safe fast-path at **0.35** (in `rules.json`). Those numbers only mean something if the probability is real. So calibration isn't cosmetic; the gates depend on it.

**Where it's fit (the leakage-safe detail):** on a **disjoint calibration slice**, domain-grouped and separate from both train and test — so calibration quality isn't measured on data the calibrator already saw. (This was itself a leakage fix.)

---

## 11. How the model is trained

🟢 "trained." This is the step-by-step for "how did you train it?" All in `train_ml_strong.py`.

1. **Load** the datasets (base + adversarial×2 + legit + fresh phishing).
2. **Clean label noise** (the A5 rules, §6): drop phishing-on-trusted-roots and shortener/free-host roots.
3. **Balance** to 50/50, capped at 150k/class.
4. **Augment — path decorrelation (the key fix, §12):** emit each URL **twice** — once bare (`host`), once with a path drawn from a **shared pool used for both classes**. Result: ~50% of *each* class is pathed, so "has a path" carries **no** label signal. (Before this, legit were mostly bare domains and phishing mostly pathed, so the model had learned the shortcut "path = phishing.")
5. **Strip the protocol** (`http://`/`https://`) so the model can't cheat on it.
6. **Grouped 3-way split** by **registrable domain** into train / calibrate / test, taken on *row indices first* so nothing is fit before the split. Three `assert …isdisjoint()` lines make any cross-split domain leak a hard crash (§12).
7. **Fit the vectorizers + scaler on the TRAIN slice only**, then `.transform()` calibrate and test. (Fitting them on the full set first — as an earlier version did — let the vocabulary peek at test rows, mildly inflating the score. Now it's leakage-free end to end.)
8. **Train** the XGBoost base model on train; **calibrate** on the disjoint calibration slice (§10).
9. **Save** four artifacts: `model.pkl`, `char_vectorizer.pkl`, `word_vectorizer.pkl`, `scaler.pkl`.

**StandardScaler** (⚪ but good to know): standardizes the 22 numeric features to mean 0 / variance 1 so no single large-magnitude feature (like URL length) dominates by scale alone. Fit on train only.

---

## 12. Data leakage

🔵 **Your single strongest talking point. Expect the deepest questions here — and welcome them.**

**From basics:** *data leakage* is when information from your test set sneaks into training, so your reported score is inflated and the model looks better than it really is. It's the most common way student ML projects quietly lie.

**The two leaks I found in my own first model:**
1. **Domain leakage.** I originally split the data by **row**. But one domain has many URL rows, so the *same domain* landed in both train and test. The model memorized domains rather than learning to generalize — and the held-out score read a fake **~98%**.
2. **The path artifact.** Legitimate examples were mostly bare Tranco domains; phishing examples were mostly full URLs with paths. So the model learned a shortcut: **"URL has a path ⇒ phishing."** That's not phishing detection, that's detecting whether someone typed a path.

**The two fixes:**
1. **GroupShuffleSplit keyed on the registrable domain** — a domain is entirely in train *or* test, never both. Now the test set measures **generalization to unseen domains**, which is the real task. (I also made a disjoint 3-way train/calibrate/test split.)
2. **Path decorrelation** (§11 step 4) — emit every URL both bare and pathed, for both classes, from the same path pool. Now path presence carries no label signal; only the host can.

**Proof it's fixed:** `path_artifact_probe.py` shows identical domains score the same bare vs pathed; `byjus.com` and its deep-path variants are all SAFE at the model level.

**The line that lands:**
> "The most valuable thing I did wasn't getting a high number — it was catching that my high number was a lie."

**"What is GroupShuffleSplit?"** 🔵
> "A train/test split that keeps all rows sharing a *group key* together. My group key is the registrable domain. So evaluation measures whether the model generalizes to domains it has never seen — not whether it memorized ones it has."

---

## 13. Accuracy & the honest numbers

🔵 "What's your accuracy?" is coming. **Never say 98%.**

| Metric | Value | What it means |
|---|---|---|
| Grouped hold-out accuracy | **~74%** | honest, leakage-free, on unseen domains |
| False-positive rate | **6.23%** | on an 80,110-URL legit sweep (`fp_sweep.py`); the **gated** metric |
| Cross-source recall | **~70.4%** | catches ~70% of phishing from a feed it never trained on, counting only novel domains |
| Homograph probe | **14/14** | look-alike spoof test cases |
| Retired, dishonest number | ~98% | leakage-inflated — **never claim it** |

### "What's your accuracy?" — the answer
> "~74% on a leakage-free, domain-grouped hold-out — and I'll tell you *why* that's the honest number and not the 98% my first split reported." (Then tell the leakage story, §12.)

### "Why do you report false-positive rate, not just accuracy?" 🔵
> "Operationally, the costly error is flagging a *real* bank or shopping site as phishing — that destroys user trust instantly. So the false-positive rate on legitimate traffic is the number that actually matters, and it's the one I *gate* on: a retrain has to stay under a 9.70% false-positive ceiling or I revert it. I improved it from 10.4% down to 6.23% across five gated retrains."

### "How is recall measured?" 🔵
> "`cross_source_recall_probe.py` scores the model on OpenPhish — a feed it never trained on — counting only *novel* registrable roots, so there's zero overlap. The blocklist and allowlist are bypassed so it measures the *model's* lexical generalization, not the blocklist trivially matching itself. ~70.4% at the 0.60 threshold."

**Honest ceiling to admit:** a genuinely tell-free brand-new domain like `fakebrand123.com` is unbeatable by any URL-only model — that's exactly what the live blocklist is for.

---

## 14. The 6-gate pipeline

🟢 Bullet 3 ("hybrid pipeline … blocklist … allowlist"). 🔵 the specific gate order. All in `main.py` + `predict_ml_only.py`.

**The big idea:** the **model runs first**, and a thin ladder of rules wraps it to handle what a URL-string model *provably can't* know. This is the "hybrid" in your bullet.

> "It's model-first. The rules are a principled wrapper around the model, not ML bolted onto a pile of rules."

The order (first match wins):

| Gate | What it checks | Outcome |
|---|---|---|
| **1. ML model** | calibrated XGBoost scores the URL | produces probability + any structural override |
| **2. Structural override** | raw-IP host, `@`-credential trick, or corroborated brand-spoof | → **PHISHING** (10.0) |
| **2b. Blocklist** | exact match in local OpenPhish/PhishTank snapshot | → **PHISHING** (9.0) |
| **2c. Allowlist** | registrable root is a globally-trusted domain | → **SAFE** |
| **3. Confident-safe fast path** | model prob < 0.35 **and** no local brand/typo/subdomain flag | → **SAFE** (fast) |
| **4. Full heuristics** | brand / typo / subdomain / IP / keyword / domain-age / SSL, then a **dampener** | → PHISHING / SUSPICIOUS / SAFE by score |

### "Why have rules at all if you have a model?" 🔵 (the key question)
> "Defense-in-depth. A URL-string model *cannot* know that one specific URL was reported to a live blacklist five minutes ago — that's reputation data, not lexical. And it should *never* flag google.com, however the features land. The rules handle those certainties; the model handles the fuzzy middle. Crucially the model runs first — the rules only override when they're certain."

### Blocklist 🟢
- A local snapshot of OpenPhish + PhishTank, loaded into an in-memory set at startup (~75k URL entries), **exact-URL match** (`main.py:176-217`).
- **"Why exact-URL, not whole-root?"** 🔵 → "Because these feeds are dominated by shared free-hosting roots (weebly, vercel…). Blocking a whole such root would nuke thousands of legit sites, so I flag only the specific reported URL."

### Allowlist / trusted roots 🟢
- ~245 major brands, **exact registrable-root match only** (`config.py:29`, `predict_ml_only.py:60`).
- **"Isn't an allowlist cheating?"** 🔵 → "It's a false-positive safety net, not the detector. It's exact-root only, so `dropbox.com.evil.xyz` is *not* trusted. And it's **not** baked into the model — I measure model quality *without* it (that's what `fp_sweep` does), so I always know the real model performance behind the net."
- Smart carve-out: for shared-hosting roots (`github.io`, `*.tumblr.com`), an exact blocklist hit *overrides* the allowlist — because their trust belongs to the platform, not the tenant.

### The structural override 🔵
In `predict_ml_only.py:76`: a brand-spoof flag alone is **not** enough to force PHISHING (a legit name can resemble a brand). It fires only when **corroborated** — brand-spoof **AND** (keyword OR suspicious TLD OR punycode OR non-ASCII host). Raw-IP host and `@`-authority each fire on their own.

### The dampener 🔵
In Gate 4, if the model is confident-safe (prob < threshold), the heuristic score is **halved** — so a legit page that trips a soft heuristic doesn't get dragged over the line when the model is sure it's fine.

---

## 15. Homograph detection

🟢 Bullet 3. 🔵 how it works. All in `features.py:34-65`.

**What it is (say this first):**
> "A homograph attack registers a domain that *looks* identical to a real brand but uses different Unicode characters — like a Cyrillic 'а' instead of a Latin 'a' in `pаypal.com`. To your eye it's PayPal; to the computer it's a totally different string."

**How I catch it — two steps:**
1. **Punycode decode** (`_decode_idn`): internationalized domains are stored as ASCII `xn--…`. I decode those labels back to the Unicode they render as, so `xn--pple-43d.com` is compared as the look-alike it actually displays.
2. **Skeleton folding** (`_skeleton`): I reduce the host to a de-confused ASCII "skeleton" — NFKD-normalize (folds accents/full-width forms), then map known confusable characters (Cyrillic/Greek look-alikes) to their ASCII twin via a `_CONFUSABLES` table. Then the **fuzzy brand match** runs against that skeleton, so the Cyrillic `pаypal` folds to `paypal` and matches the real brand → flags.

Two of the 22 features back this: `20` (punycode present) and `21` (non-ASCII host after decode). A pure-ASCII legit host is unchanged by all this, so **real `paypal.com` stays SAFE.** `homograph_probe.py` passes **14/14**.

**Honest nuance (shows depth):**
> "The skeleton rule catches single-character Unicode and digit swaps. A *multi*-character ASCII trick like `rn`→`m` (`arnazon.com`) isn't a confusable fold — that one is caught by the ML model via the character TF-IDF features, not by this rule. I know exactly which technique each layer covers."

---

## 16. FastAPI backend + SQLite

🟢 Bullet 2.

### FastAPI 🟢
The backend (`main.py`) exposes:
- `POST /predict_url` — the main scan endpoint.
- `POST /report_false_positive` — users flag a wrong verdict (logged for retrain triage).
- `GET /stats`, `GET /recent` — dashboard data.
- `GET /health` — reports version, model, thresholds.

**"Why FastAPI, not Flask/Django?"** 🔵
> "Three reasons. It's **async**, so a slow network call — a WHOIS lookup can hang for seconds — runs in a worker thread via `asyncio.to_thread` and doesn't block other requests. It has **built-in Pydantic validation**, so a malformed request body is rejected cleanly before my code runs. And it **auto-generates OpenAPI docs**. Django would be overkill for a handful of JSON endpoints with no templating or ORM needs."

**Real-time detail worth stating:** CPU-bound work (TF-IDF transform + XGBoost predict) also runs via `asyncio.to_thread`, so a burst of requests can't serialize on the event loop. Confident-safe URLs return in milliseconds because the fast path skips the network checks entirely.

**Input hardening** (⚪ but impressive): `_normalize_url` trims, caps length, **de-fangs** threat-intel notation (`hxxp://`, `evil[.]com` → live URL), and collapses redundant slashes — all before analysis.

### SQLite event logging 🟢
`database.py` writes every scan to a `phishing_events` table: `id, type, content (the URL, capped 500 chars), result, risk_score, response_time, timestamp`, indexed on `timestamp` and `result`.

**"What do you log and why?"** 🔵
> "Every verdict — the URL, the result, the risk score, and the response time — so the dashboard can show scan history and KPIs, and so I have data to triage false positives. Writes run in a worker thread and any DB error is swallowed with a log line: **logging is a side effect, so a locked DB or full disk must never turn a good verdict into a 500.** The schema is standard SQL, so swapping SQLite for Postgres in production is a one-line change."

---

## 17. Chrome extension

🟢 Bullet 2 ("Chrome (Manifest V3) … in-page phishing warnings").

**What it does:** checks every page you visit against the same backend API in the background, and injects an in-page warning banner if a page is flagged.

**Manifest V3 (MV3)** 🔵 — know what it is:
> "MV3 is Chrome's current extension platform. The big changes from MV2 are a **service worker** instead of a persistent background page, and a **stricter Content Security Policy** that bans runtime code evaluation like `eval` and `new Function`. My `manifest.json` declares `manifest_version: 3`, a background service worker, and the `scripting` + `storage` permissions."

**The two security bugs you fixed (great story — shows security awareness):** 🔵
1. **CSP violation:** the old banner-injection code used `new Function()`, which MV3's CSP blocks — so it silently never ran. I rebuilt it with `chrome.scripting.executeScript` plus `createElement`/`textContent`.
2. **DOM-XSS:** an attacker-controlled URL/reason was being rendered via `innerHTML` — a cross-site-scripting sink. I switched every injection point to `textContent`, which never interprets HTML.

**Be honest about distribution:** 🟢
> "It loads **unpacked** as a portfolio project — it's not published on the Chrome Web Store. That's exactly why my bullet says 'Built,' not 'Deployed.'"

---

## 18. END-TO-END WALKTHROUGH

🟢 **The money question: "walk me through what happens end to end."** Memorize this flow. Trace a real URL.

**Example: a user's extension hits `http://paypa1-secure-login.tk/account`.**

1. **Extension → API.** The Chrome service worker sends the URL to `POST /predict_url` on the FastAPI backend.
2. **Normalize.** `_normalize_url` trims it, caps length, de-fangs any `hxxp`/`[.]`, collapses slashes.
3. **Gate 1 — model scores it.** `predict_ml` runs in a worker thread:
   - **Loopback check** on the parsed host — no.
   - **Allowlist check** — `paypa1-secure-login.tk` is not a trusted root — no.
   - **Feature extraction** — 22 features: suspicious TLD `.tk` (16), brand-spoof `paypa1`≈`paypal` (8), keyword `login`/`secure`/`account` (6), etc.
   - **Structural override test:** brand-spoof (8) corroborated by keyword (9) and suspicious TLD (16) → fires.
   - Returns `(1, 0.999, "Critical: Structural security risk detected")`.
4. **Gate 2 — structural override** sees "Critical" → verdict **PHISHING**, score **10.0**, reason returned.
5. **Log.** The event is written to SQLite in a worker thread (never blocks or breaks the response).
6. **Response.** JSON goes back: `result: PHISHING`, `risk_score: 10.0`, `reasons: [...]`, plus domain-age/SSL meta.
7. **Extension renders** an in-page red warning banner using `textContent` (XSS-safe).

**Contrast — a clean URL `https://github.com`:**
1–2. Same normalize.
3. Gate 1: allowlist contains `github.com` → returns `(0, 0.001, "Globally trusted domain")`.
4. Gate 2 (structural): not critical. Gate 2b (blocklist): not listed. **Gate 2c (allowlist): matches → SAFE**, returns immediately — no WHOIS, no SSL, millisecond response.

**Contrast — a genuinely ambiguous URL** (no allowlist hit, model prob ~0.5): falls through to **Gate 4**, which adds up weighted heuristics (brand/typo/subdomain/IP/keyword/domain-age/SSL), applies the dampener if the model leans safe, and maps the final score to PHISHING / SUSPICIOUS / SAFE.

> **The one-liner to open with:** "The model scores first; then a ladder of gates resolves the certainties — structural red flags and the blocklist force PHISHING, the allowlist forces SAFE, and only the genuinely uncertain URLs reach the full weighted heuristics."

---

## 19. Testing & deployment

### Testing ⚪ (but a strong signal — mention it)
- **128 pytest cases** across 11 files, offline + deterministic (~8s).
- They test **behavioral contracts**, each tied to a real past bug: the feature vector is always length 22; an email in a *query string* never triggers the `@` rule; a stale blocklist entry can't flip `google.com`; the 14/14 homograph set holds; gate ordering is correct.
- Plus **statistical probes** (`fp_sweep.py`, `cross_source_recall_probe.py`, `path_artifact_probe.py`) that own the quality numbers.
- You can run it live: `cd backend && python -m pytest` → 128 passed.

> "The tests **lock behavior**; the probes **own the numbers**. Each test exists because something broke once."

### Deployment ⚪ (be honest)
- Backend (FastAPI) on **Render**, static frontend on **Vercel**, config in `render.yaml` + `vercel.json`.
- **"Is it live / does it have users?"** → *"It's deployed and functional as a portfolio project — not a product with a user base."* Never imply real users.

---

## 20. Full tech stack

🟢 = on your header. The rest is for conversation — know what each does, don't lead with it.

| Layer | Tech | On resume? |
|---|---|---|
| Language | Python 3.12 | 🟢 header |
| ML model | **XGBoost** 2.0.3 | 🟢 header |
| ML tooling | scikit-learn (TF-IDF, StandardScaler, calibration, GroupShuffleSplit) | ⚪ |
| Numerics | numpy, scipy, pandas | ⚪ |
| Fuzzy match | rapidfuzz (brand similarity) | ⚪ |
| Web framework | **FastAPI** + uvicorn + pydantic | 🟢 header |
| Database | **SQLite** (stdlib `sqlite3`) | 🟢 bullet 2 |
| Enrichment | python-whois, `ssl`/`socket` (domain age, cert check) | ⚪ |
| Frontend | vanilla HTML/CSS/JS | ⚪ |
| Browser | **Chrome extension (MV3)** | 🟢 header + bullet 2 |
| Analytics | Power BI (CSV star-schema export) | ⚪ |
| Testing | pytest (128 cases) | ⚪ |
| Deploy | Render + Vercel, private GitHub | ⚪ |

**Why the helper libraries are NOT on your header:** 🔵
> "numpy, scipy, rapidfuzz, python-whois — these are implementation details. Putting them on a resume invites low-value trivia questions and clutters the headline. I headline the recognizable, decision-level tools (Python, XGBoost, FastAPI, Chrome extension) and keep the rest for conversation, where I can explain exactly what each one does."

That answer itself impresses — it shows judgment about signal vs noise.

---

## 21. Mock interview Q&A

**Q: Walk me through the project end to end.** → §18 (lead with the one-liner).

**Q: Supervised or unsupervised?** → "Supervised binary classification — labelled phishing vs legitimate, model outputs a phishing probability." §5.

**Q: What's your accuracy?** → "~74% honest, leakage-free — and here's why it's not the 98% my first model reported…" §13 → §12.

**Q: What is XGBoost?** → trees → boosting → gradient boosting → regularized. §9.

**Q: Why XGBoost and not a neural net?** → sparse tabular data, non-linear interactions, fast on CPU, less overfit, explainable. §9.

**Q: What does "calibrated" mean?** → raw scores → true probabilities via isotonic; my thresholds are probabilities so they must be honest. §10.

**Q: Name some features.** → length, entropy, keyword count, fuzzy brand similarity, `@`-authority, raw-IP, suspicious TLD, punycode, non-ASCII host. §7.

**Q: Does TF-IDF even matter at weight 0.05?** → "Secondary signal; numeric features dominate; learned block-weights are future work." §8 (the trap — don't oversell it).

**Q: Why rules if you have a model?** → defense-in-depth; model can't know live reputation, must never flag google.com; model runs first. §14.

**Q: Isn't the allowlist cheating?** → FP safety net, exact-root only, not baked into the model, measured without it. §14.

**Q: How does homograph detection work?** → punycode decode + skeleton fold + fuzzy brand match; `rn`→`m` is the model's job not the rule's. §15.

**Q: Why FastAPI?** → async, Pydantic validation, auto-docs. §16.

**Q: Why SQLite — would it scale?** → "Fine for a portfolio project; the schema is standard SQL so swapping to Postgres is a one-line `DB_PATH` change." §16.

**Q: Is it live / does it have users?** → "Deployed as a portfolio project, no user base." §19.

**Q: What was the hardest/most valuable thing?** → the leakage story. §12.

**Q: What would you improve?** → learned feature-block weights; page-content analysis (currently URL-only); a live authenticated blocklist API instead of a snapshot. (All honest, all documented.)

---

## 22. Honesty rules

These protect you. Breaking one is how a good project interview goes bad.

1. **Never say 98%.** Always ~74% honest + the leakage fix. The rigor impresses more than a fake number.
2. **It's URL-string-only.** It can't see page content or follow redirects. Say so — it's "future work," not a hidden gap.
3. **Datasets are public feeds** (Tranco, OpenPhish, PhishTank, Phishing.Database, Kaggle). Say so.
4. **TF-IDF is secondary** (0.05 weight). Don't present it as the core.
5. **"Deployed" ≠ "has users."** Portfolio project.
6. **The extension is loaded unpacked**, not on the Web Store. That's why it's "Built," not "Deployed."
7. **If you don't know something, call it a documented limitation.** The project has an honest answer for every weak spot — that's *why* it survives scrutiny.

> Lead with the leakage story. Stay honest. Go as deep as they want — every claim in this guide maps to a file, a number, or a test you can run on the spot.
