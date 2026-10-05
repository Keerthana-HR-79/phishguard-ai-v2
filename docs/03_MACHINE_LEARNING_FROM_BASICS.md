# 03 — Machine Learning, From Basics

This is the deepest document. It explains, assuming **no prior ML knowledge**: what kind of
learning this is, how a URL becomes numbers, what TF-IDF and scaling do, **how XGBoost works from
the ground up**, how the model is trained, the data-leakage story that defines this project, the
complete v3.0→v3.5 retrain history with exact metrics, and how the finished model actually
classifies a URL.

---

## 1. What kind of machine learning is this?

### Supervised vs unsupervised (the answer: **supervised**)

- **Supervised learning** = you train on examples that are **already labeled** with the right
  answer. You show the model thousands of URLs each tagged `phishing` or `legitimate`, and it
  learns the mapping from URL → label.
- **Unsupervised learning** = no labels; the algorithm finds structure/clusters on its own
  (e.g. "group similar URLs"). Useful for discovery, but it can't tell you "this is phishing"
  because it was never told what phishing *is*.

PhishGuard is **supervised** because we *have* ground-truth labels (from threat feeds like
OpenPhish/PhishTank for phishing, and top-sites lists like Tranco for legitimate), and we want a
specific yes/no answer.

### Classification vs regression (the answer: **classification**)

- **Classification** = predict a **category** (phishing or legitimate). ← this project
- **Regression** = predict a **number** (e.g. house price).

More precisely it's **binary classification**: exactly two classes, encoded **phishing = 1,
legitimate = 0**. The model outputs a **probability** between 0 and 1 (how likely the URL is
phishing), and a **threshold** (0.60) converts that probability into the yes/no decision.

> **Interview one-liner:** "It's supervised binary classification. The model outputs a calibrated
> probability of phishing, and a tuned threshold turns that into the SAFE/SUSPICIOUS/PHISHING
> verdict."

---

## 2. From a URL to numbers (feature engineering)

A machine-learning model can't read a string; it needs **numbers**. We convert each URL into
numbers in **three parallel blocks**, then stack them into one big feature row:

1. **22 hand-built numeric features** — expert signals about the URL's structure.
2. **Character TF-IDF** — 3-to-5-character substrings of the URL (3000 dimensions).
3. **Word TF-IDF** — word-like tokens in the URL (1000 dimensions).

### 2.1 The 22 features (`features.py`) {#the-22-features}

Each captures a signal a security analyst would look at. (`feats[i]` = feature at index `i`.)

| # | Feature | Why it signals phishing |
|---|---------|-------------------------|
| 0 | URL length ÷ 100 | Phishing URLs are often abnormally long (padding, redirects) |
| 1 | Number of dots `.` | Many subdomains (`a.b.c.d.evil.com`) hide the real domain |
| 2 | Number of hyphens `-` | `secure-login-paypal.com` style padding |
| 3 | Number of slashes `/` | Deep paths |
| 4 | Number of digits | `paypa1`, `g00gle`, IP-like hosts |
| 5 | Shannon entropy | Random-looking hostnames (`x9f2k1z.com`) score high |
| 6 | Phishing-keyword count in URL | login/verify/secure/account/update… present |
| 7 | Max brand fuzzy similarity ÷ 100 | How close any piece is to a known brand |
| 8 | **Brand-spoof flag** | A piece look-alikes a brand but isn't that brand's real domain |
| 9 | Brand-spoof **AND** keyword present | The two together — much stronger signal |
| 10 | **Raw IP address** in host (regex) | `http://192.168.3.4/login` — legit sites use names |
| 11 | **`@` in the authority** | `legit.com@evil.com` — browser goes to `evil.com` |
| 12 | `@` with a dot after it (in authority) | Refines the credential-hiding trick |
| 13 | Path segment count | Deep, stacked paths |
| 14 | Hyphen in the **domain** | Domain-level padding specifically |
| 15 | Subdomain depth | `login.secure.account.evil.com` |
| 16 | **Suspicious TLD** | `.xyz .tk .zip .top …` cheap/abused TLDs |
| 17 | `localhost` in URL | Dev/loopback marker |
| 18 | Host keyword-token count | Keywords appearing specifically in the host |
| 19 | Hyphens in the host | Host-level padding |
| 20 | **Punycode** `xn--` in host | Homograph attack marker (IDN encoding) |
| 21 | **Non-ASCII host** after IDN decode | Cyrillic/Greek look-alike characters |

**Homograph handling (features 7, 8, 20, 21):** attackers register `xn--pypal-4ve.com`, which a
browser renders as "pаypal" using a Cyrillic 'а'. `features.py` decodes the punycode
(`_decode_idn`), maps confusable characters to their ASCII twins (`_skeleton` + `_CONFUSABLES`,
using Unicode NFKD normalization), and folds the skeleton into the brand fuzzy match — so the
homograph fires the brand-spoof feature just like an ASCII typosquat would.

**Fuzzy brand matching (feature 7/8):** uses **rapidfuzz** `fuzz.ratio > 85`, after normalizing
leetspeak (`0→o`, `1→l`, `3→e`) and only on pieces ≥ 4 chars (to avoid trivial collisions). So
`paypa1` → normalize → `paypal` → ratio 100 → brand-spoof.

**Robustness:** any exception during extraction returns `[0]*22`, so a malformed URL degrades to
"no signal" instead of crashing inference.

### 2.2 TF-IDF from basics (`char_vectorizer`, `word_vectorizer`)

**The problem it solves:** the 22 features are expert-chosen, but they can't capture *every*
telltale substring. TF-IDF lets the model learn from the **raw text of the URL** too.

**TF-IDF = Term Frequency × Inverse Document Frequency.**
- **Term Frequency (TF):** how often a term appears in *this* URL.
- **Inverse Document Frequency (IDF):** how *rare* that term is across **all** URLs. Terms that
  appear everywhere (like `http`, `com`) get a low weight; distinctive terms get a high weight.
- Multiply them: a term that appears in this URL **and** is rare overall gets a high score.

**Two vectorizers, two granularities:**
- **Character n-grams (3–5):** `TfidfVectorizer(analyzer="char", ngram_range=(3,5),
  max_features=3000)`. It slides a window over the URL producing substrings like `pay`, `aypa`,
  `paypa`, `up-`, `.xy`, `xyz`. This catches misspellings and odd character patterns even in
  never-before-seen words. **3000** most-informative substrings are kept.
- **Word tokens:** `TfidfVectorizer(max_features=1000)`. Splits on word boundaries →
  `secure`, `update`, `login`. Catches keyword-level signals. **1000** kept.

The result of each is a **sparse vector** (mostly zeros — a given URL contains only a handful of
the 3000/1000 possible terms), which scipy stores compactly.

**Why both character and word:** character n-grams generalize to *unseen* words and typos (`paypa1`
shares n-grams with `paypal`); word tokens capture whole-keyword meaning. Together they cover
"looks weird at the character level" and "contains a suspicious word".

### 2.3 StandardScaler (the 22 numeric features)

The 22 features live on wildly different scales (a length like 137 vs a 0/1 flag). **StandardScaler**
transforms each feature to **mean 0, standard deviation 1** ( `z = (x − mean) / std` ). This keeps
any one large-magnitude feature from dominating and makes the numeric block well-behaved.

Crucially (M10 fix), the scaler's mean/std are learned from the **training slice only**, then
merely *applied* to calibration/test data — so no information about the test set leaks into
preprocessing.

### 2.4 Stacking + the block weights `[0.05, 0.05, 15]`

The three blocks are combined into one row with **`config.stack_features()`**:
```
X = hstack([ X_char * 0.05,  X_word * 0.05,  X_numeric * 15 ])
```
- The char/word TF-IDF blocks are **down-weighted ×0.05** and the 22 numeric features **up-weighted
  ×15**. This deliberately makes the **hand-built expert features the dominant signal**, with TF-IDF
  as a supporting lexical texture.
- This exact weighting is the **single source of truth** in `config.py` (the H3 fix), called by
  **both** the trainer and the server, so training geometry == serving geometry. Golden-vector
  tests lock it.

> **Honest caveat (a documented limitation, good to mention):** the ×0.05 makes the ~4000 TF-IDF
> features individually minor versus the 22 numeric ones — a known trade-off (C3 in the audit).
> The chosen design leans on the interpretable expert features; letting XGBoost learn the scales
> freely is a documented future experiment.

---

## 3. The datasets (what the model learns from)

All labeled CSVs have two columns: **`url`** and **`type`** (`phishing` / `legitimate`).

| Dataset | Rows | Role |
|---|---|---|
| **`final_dataset.csv`** | **1,508,510** (~1,345,737 legit + ~162,313 phishing) | The main training corpus |
| **`fresh_phishing.csv`** | **154,798** | Freshly-mined **novel + clean** phishing roots (the v3.3 upgrade) |
| **`adversarial_phishing.csv`** | **11,930** | Synthesized brand/keyword spoofs to teach the hard cases |
| **`legit_urls.csv`** | **80,111** | Curated legit set — used as the **FP-sweep** benchmark |
| **`fresh_holdout.csv`** | **5,001** | Unseen phishing domains, **never trained on** — recall benchmark |

**Raw feeds** (`data/raw/`, used to build the above or as the runtime blocklist):
- **`openphish.txt`** (~600 live URLs) — committed; the runtime **blocklist**.
- **`phishtank.csv`** (~58,082) — phishing feed (gitignored; backend degrades gracefully without it).
- **`tranco.csv`** (1,000,000) — top-sites list → the legitimate class seed.
- **`kaggle.csv`** (~450,177) — a public phishing/legit dataset.
- **`phishing-domains-ACTIVE.txt`** (391,986) — Phishing.Database ACTIVE; mined for fresh data.

### Why these sources (and why chosen)

- **OpenPhish / PhishTank** — the standard, community-trusted **live phishing** feeds. Real
  attacker URLs, not synthetic. OpenPhish is free and refreshable, so it doubles as the runtime
  blocklist.
- **Tranco** — a **research-grade top-sites ranking** that's more manipulation-resistant than raw
  Alexa/Cisco lists. It seeds the "legitimate" class. (Its known weakness — it contains
  shorteners/free-hosts/compromised sites — is exactly the label noise the A5 cleaning removes.)
- **Phishing.Database ACTIVE** — a **large, currently-live** domain feed. It was the key to fixing
  the "clean bare-domain phishing" blind spot: mining **novel** (unseen root) + **clean** (not on
  the legit/trusted/shortener lists) bare domains gave the model real examples of the hardest slice.
- **Kaggle** — adds public-dataset breadth and label diversity.

### Why not just one dataset / why the balance matters

Real internet traffic is overwhelmingly legitimate; the corpus reflects that skew (~1.35M legit vs
~162k phishing) but training samples toward balance (`MAX_PER_CLASS = 150,000`) so the model sees
enough phishing to learn it, without a single feed's quirks dominating. Mixing feeds
(OpenPhish + PhishTank + Kaggle + Phishing.Database) reduces **source bias** — a model trained on
one feed learns that feed's formatting, not "phishing".

---

## 4. How XGBoost works — from the ground up

This is the algorithm interviewers most want you to explain. Build it up in five layers.

### Layer 1 — A single decision tree

A **decision tree** asks yes/no questions about features and follows branches to a leaf that gives
an answer. For a URL:
```
             is feats[11] (@ in authority) == 1?
                    /yes                \no
             PHISHING            is feats[16] (suspicious TLD)==1?
                                       /yes            \no
                             is brand-spoof==1?      ... (more splits)
                               /yes      \no
                           PHISHING     leans legit
```
Each split is chosen to best separate phishing from legit at that node. One tree is simple and
interpretable but **weak** — it either oversimplifies (too shallow) or memorizes/overfits (too
deep).

### Layer 2 — Ensembles (many trees beat one)

Combine **many** trees so their mistakes cancel out. Two ways to build the ensemble:
- **Bagging (Random Forest):** build many deep trees **independently, in parallel**, each on a
  random subset of data/features, then **average** their votes. Reduces variance.
- **Boosting (XGBoost):** build trees **sequentially**, where **each new tree focuses on the
  errors the previous trees made**. Reduces bias *and* variance, usually to higher accuracy.

PhishGuard uses **boosting**.

### Layer 3 — Gradient boosting (the core idea)

"Gradient boosting" means each new tree is trained to predict the **residual error** (the gradient
of the loss) of the current ensemble:

1. Start with a baseline guess (e.g. the overall phishing rate).
2. Compute how wrong it is on each example (the residual).
3. Train a **new small tree** to predict those residuals.
4. Add that tree to the ensemble, scaled by a **learning rate** (so no single tree over-corrects).
5. Repeat for N trees. Each tree nudges the prediction closer to correct, concentrating on the
   examples still being gotten wrong.

The final prediction is the **sum of all trees'** contributions, squashed to a 0–1 probability.
"Gradient" = it uses the gradient of the loss function (here **log-loss**, the right loss for
probabilistic binary classification) to know which direction to correct.

### Layer 4 — What makes it "eXtreme" (XGBoost specifics)

XGBoost is a highly optimized gradient-boosting implementation that adds:
- **Regularization** built into the split objective (penalizes overly complex trees) → resists
  overfitting.
- **Second-order optimization** (uses gradient *and* curvature/Hessian) for better, faster steps.
- **Smart tree construction** (histogram-based split finding) → fast on large data.
- **`scale_pos_weight`** to handle class imbalance (kept at 1 here because sampling balances the
  classes).

### Layer 5 — The exact hyperparameters used (and why)

From `train_ml_strong.py`:
```python
XGBClassifier(
    n_estimators=400,       # 400 trees — enough to learn, bounded to limit overfit + keep inference fast
    max_depth=7,            # each tree up to depth 7 — captures feature interactions, not so deep it memorizes
    learning_rate=0.05,     # small steps — each tree corrects gently; pairs with many trees for stability
    scale_pos_weight=1,     # classes are balanced by sampling, so no extra positive weighting
    eval_metric="logloss",  # optimize probabilistic correctness (right for a calibrated classifier)
    random_state=42,        # M11: reproducible
    n_jobs=1,               # M11: deterministic (no parallel-order nondeterminism)
    verbosity=0,
)
```
**How to justify each:**
- `n_estimators=400` + `learning_rate=0.05` — the classic boosting trade: **many trees, small
  steps**. Small steps prevent any one tree from overshooting; 400 trees give enough capacity.
- `max_depth=7` — deep enough for the multi-feature **interactions** phishing needs
  (hyphen × brand × TLD), shallow enough to generalize.
- `random_state=42, n_jobs=1` — makes training **bit-reproducible**, which is what makes the golden
  model-score tests meaningful (M11).

### Why XGBoost and not the alternatives (deep version)

- **vs Logistic Regression:** LR is linear — it draws one straight boundary. Phishing is defined by
  **feature interactions** ("suspicious only when hyphen AND brand-spoof AND weird TLD co-occur").
  Trees model these conjunctions natively; LR needs every interaction hand-coded. Trees win on this
  feature set.
- **vs Random Forest:** RF averages independent trees (bagging); XGBoost's sequential
  error-correction (boosting) plus regularization and learning-rate control typically edges out RF
  in accuracy and gives finer control. RF is the closest runner-up and a legitimate answer to
  "what else did you consider?"
- **vs Deep Learning:** on **tabular** features, gradient-boosted trees reliably match or beat
  neural nets while needing **less data, less compute, and offering explainability** — all three
  of which matter for a security tool and a browser extension that scores every page. A char-level
  neural net on the raw URL is the research-y alternative; it wasn't worth the cost/opacity here.

---

## 5. Calibration — turning scores into honest probabilities

Raw classifier outputs aren't necessarily true probabilities (a raw "0.9" might not mean "90%
likely"). Because the **entire decision ladder uses probability thresholds** (0.35, 0.60, 0.55),
the probabilities must be **trustworthy**.

**`CalibratedClassifierCV(base_model, cv="prefit", method="isotonic")`** fixes this:
- **Isotonic regression** learns a monotonic mapping from raw score → true empirical probability,
  fit on a **held-out calibration slice** (disjoint by domain from both train and test).
- After calibration, "0.60" genuinely means "~60% of URLs scoring this are phishing", so the 0.60
  decision threshold is meaningful.

**Why isotonic (not Platt/sigmoid scaling):** isotonic is non-parametric and flexible; with enough
calibration data it fits the true reliability curve better than a fixed sigmoid. (A visible side
effect: isotonic **quantizes** probabilities into steps, which is why some nearby thresholds behave
identically — noted in the tuning history.)

---

## 6. How the model is trained (the pipeline, step by step)

`train_ml_strong.py` (header v3.1, producing model v3.5) runs offline and emits the four artifacts.

1. **Load** `final_dataset.csv`, `adversarial_phishing.csv`, `fresh_phishing.csv`, `legit_urls.csv`.
2. **Label-noise cleaning (A5):**
   - (a) Drop **phishing** rows whose registrable root is a curated **trusted root** (a feed
     attaching a phishing path to `byjus.com`/`sbi.co.in` must never train as a phishing *example*).
   - (b) Drop **shortener/free-host** roots (`bit.ly`, `github.io`, …) from **both** classes — a
     shared root hosts thousands of unrelated sites, so "root ⇒ class" is pure noise there.
   - (c) A more aggressive rule ("drop any phishing root also seen in legit") was **tried and
     reverted** — it stripped real compromised-host phishing and pushed FP *up* 10.4%→13.8%.
3. **Balance** to `MAX_PER_CLASS = 150,000` per class (`SEED = 42`).
4. **Augment (path decorrelation, `url_augment.py`):** emit each URL **bare and pathed**, drawing
   paths from a shared pool for **both** classes, and a deep 2–7-segment path **35%** of the time.
   → path presence/depth/keywords carry **no** class signal (kills the "has a path ⇒ phishing"
   artifact).
5. **Split by domain (GroupShuffleSplit):** hold out **20% test**, then **20% calibration**,
   grouping by **registrable domain** so **no domain appears in more than one split**. This is the
   anti-leakage core.
6. **Fit preprocessing on TRAIN ONLY (M10):** fit `char_vec`, `word_vec`, and `StandardScaler` on
   the **train slice**; only *transform* calibration/test. No preprocessing leakage.
7. **Build features:** `stack_features([char*0.05, word*0.05, numeric*15])`.
8. **Train XGBoost** on the train slice (the hyperparameters in §4.5, deterministic).
9. **Calibrate** with isotonic regression on the disjoint calibration slice (`cv="prefit"`).
10. **Evaluate** on the untouched test slice → the honest, leakage-free metrics.
11. **Save** `model.pkl`, `char_vectorizer.pkl`, `word_vectorizer.pkl`, `scaler.pkl`.

Every retrain **backs up the previous artifacts first** and is **gated**: if the model-only
false-positive rate regresses past **9.70%** on the 80k sweep, the retrain is **reverted**.

---

## 7. The data-leakage story (the most important part of the whole project)

This is the narrative that makes the project stand out. Tell it in three beats.

### Beat 1 — The lie: "98% accuracy"

The first model reported **~98% accuracy**. That number was **fake**, for two reasons:

1. **Domain leakage.** The original split was **row-level** (`train_test_split`). But one domain
   produces many rows (many paths). So `byjus.com/a` could be in *train* and `byjus.com/b` in
   *test*. The model **memorized domains** it had already seen, then "passed" the test on those same
   domains. That's studying the exam answers.
2. **A path artifact (shortcut).** Legitimate examples were mostly **bare Tranco domains**, while
   phishing examples were **full URLs with paths**. So the model learned the shortcut **"URL has a
   path ⇒ phishing."** Proof: `byjus.com` scored 0.004 (SAFE) but `byjus.com/home` scored 0.999
   (PHISHING) — same safe site, opposite verdict, purely because of a path.

### Beat 2 — The audit and the honest number

The fix (v3.0):
- **GroupShuffleSplit by registrable domain** → no domain in both train and test. The score now
  measures **generalization to unseen domains**, not memorization.
- **Path decorrelation** → both classes get bare and pathed forms, so a path is no longer a class
  signal.
- **Three-way disjoint split** → calibration fit on its own slice, not on the test set.

Honest result: **~77% (later ~74% after M10 closed the last leak)** on ~13,700 unseen domains.
Lower number, but **real**. `byjus.com` and all its path variants now score SAFE.

### Beat 3 — Then genuinely improving the honest model

With an honest yardstick, five documented retrains actually moved the real metrics (next section).

> **Why this story wins interviews:** almost every student project reports an inflated in-sample
> accuracy. Catching your *own* leakage, quantifying the damage, fixing the methodology, and then
> improving the honest number demonstrates exactly the maturity real ML work requires.

---

## 8. The complete retrain history (v3.0 → v3.5) with exact metrics

The canonical source is [`MODEL_AUDIT.md`](../MODEL_AUDIT.md). Summary of every version:

| Version | Date | What changed | Key measured effect |
|---|---|---|---|
| **(original)** | — | Row-split, path artifact, calibration on test set | "~98%" — **retired as leakage-inflated** |
| **v3.0** | 2026-09-22 | Killed path artifact (decorrelated paths); scoped `@` to authority; **GroupShuffleSplit** by domain; 3-way disjoint split | **Honest ~77%** on 13,696 unseen domains (legit recall 0.91, phishing precision 0.83) |
| **v3.1** | 2026-09-23 | Brands 13→32, keywords 12→41, TLDs 9→19; **punycode/IDN homograph** (features 20/21, 20→22 features); SSL de-weighted; brand-spoof override requires corroboration | Model-only accuracy 67.5%→**72.5%**; homograph probe **14/14** |
| **v3.2b** | 2026-09-24 | Host-level **label-noise cleaning** (A5 a+b); byjus deep-path fixed at 3 layers; dead PhishTank POST → **local blocklist** | FP sweep **10.37% → 9.70%** (the hard ceiling); homograph held 14/14 |
| **v3.3** | 2026-09-24 | **Fresh data**: mined 159,797 novel+clean bare phishing roots (Phishing.Database ACTIVE); `MAX_PER_CLASS` 50k→150k; **threshold 0.5→0.6** | FP **9.70%→6.39%** *and* bare-domain recall **24.9%→54.9%** (2.2×); at equal FP, **61.1% vs 24.9%** — dominates |
| **v3.4** | 2026-09-25 | **Parent-vs-path** generalization fix (deep-path augmentation 0.15→0.35, depth 6→7) | Non-allowlisted parent/path flips **5/9 → 0/9**; FP 6.39%→6.91% (≪ 9.70%); recall 54.9%→56.7% |
| **v3.5** | 2026-09-28 | **Correctness retrain**: M10 fit preprocessing on train-only; M11 deterministic (`random_state`, `n_jobs=1`); H3 single-source feature weights | FP **6.91% → 6.23%**; equal-FP recall **61.2% → 61.3%**; homograph 14/14; **128** tests; honest acc **~74%** |

**Serving-only improvements (no model retrain, so the FP gate is untouched):**
- **backend v2.9** (keyword rule): `KEYWORD_MIN_PROB` 0.40 → **0.55** — the keyword bump only
  corroborates once the model already leans phishing (measured trade: −13 phishing, +46 legit fixed).
- **backend v3.0–v3.0.2** (2026-09-27): the blocklist became a **decisive gate** (2,745
  weaponized-host URLs un-swallowed); a **shared-hosting carve-out** over the allowlist;
  **allowlist-integrity SAFE gate** (fixed `microsoft.github.io` false SUSPICIOUS).
- **backend v3.1.0** (2026-09-28): full **security/robustness hardening** (parsed-host checks,
  off-loop inference/logging, CSV-injection guard, DOM-XSS fix, MV3 banner rebuild, timeouts).

### The metric journey in one glance

- **Model-only false-positive rate:** 10.37% → 9.70% → 6.39% → 6.91% → **6.23%** (hard ceiling
  9.70%, decisively cleared).
- **Unseen-phishing recall (same-feed holdout):** ~24.9% → 54.9% → 56.7% → 55.6% (at equal FP the
  model **dominates** every prior version).
- **Cross-source recall** (unseen feed AND unseen domain — the honest hardest test): **70.4%**.
- **Homograph/typosquat probe:** **14/14** held across every version since v3.1.
- **Honest grouped accuracy:** ~77% → **~74%** (lower only because M10 removed the *last* bit of
  optimism — it's now honest end-to-end).

### Honest limits still true (say these, don't overclaim)

- A **URL-string-only** model cannot see page content, redirects, or forms — so a **genuinely
  tell-free** brand-new domain (`fakebrand123.com`) is a **lexical ceiling** no URL-only model
  repeals. That's covered at runtime by the **blocklist**, not the model.
- Compromised-host phishing on a *legit* root (16–21% of live feeds) is a lexical blind spot **by
  construction** — again the blocklist's job.
- **B4** (folding domain-age/cert-age into the model) was **investigated and rejected on evidence**:
  among still-live phishing, age is statistically indistinguishable from legit; the only separator
  ("still resolves") is a takedown artifact that would teach "unreachable ⇒ phishing".

---

## 9. How the finished model actually classifies a URL (end to end)

Putting it together — for a URL that isn't short-circuited by loopback/allowlist/structural rules:

1. **Extract** the 22 features (`features.py`).
2. **Transform** the URL string with the char and word TF-IDF vectorizers.
3. **Scale** the 22 features with the fitted StandardScaler.
4. **Stack** `[char*0.05, word*0.05, numeric*15]` into one sparse row (`stack_features`).
5. **Predict:** the calibrated XGBoost outputs `prob` = P(phishing). Internally, all 400 trees vote,
   their contributions sum, the sum is squashed to a probability, and isotonic calibration maps it
   to an honest probability.
6. **Decide:** `pred = 1 if prob > 0.60 else 0`.
7. **Hand off** `(pred, prob, override_reason)` to the serving ladder, which combines it with the
   blocklist/allowlist/heuristics to produce the final **SAFE / SUSPICIOUS / PHISHING** verdict and
   the **0–10 risk score** (doc 04).

**"How does it detect phishing" in one paragraph for an interview:** *"It converts the URL into
~4000+22 numerical signals — expert structural features plus character and word TF-IDF — and a
calibrated XGBoost ensemble of 400 gradient-boosted trees outputs a phishing probability. Trees are
ideal here because phishing is defined by interactions between signals. That probability, made
honest by isotonic calibration and a leakage-free domain-grouped evaluation, is then thresholded
and combined with a known-bad blocklist, a trusted-domain allowlist, and structural override rules
to produce the final verdict."*

Next: [04_RULES_AND_DETECTION_LOGIC.md](04_RULES_AND_DETECTION_LOGIC.md) — the complete 6-gate
ladder and every rule.
