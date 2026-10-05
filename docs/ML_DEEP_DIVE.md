# PhishGuard AI — Machine Learning Deep Dive
*The ML and model side, in full. Every term defined from basics and tied to where it lives in the project. Verified against `train_ml_strong.py`, `features.py`, `config.py`, `predict_ml_only.py` (model v3.5).*

> Read this with the [Interview Master Guide](INTERVIEW_MASTER_GUIDE.md). That one covers the whole system; **this one is only the brain** — the model, the training, the metrics, and the "why XGBoost" argument.

---

## Table of contents
1. [The one-paragraph answer](#1-the-one-paragraph-answer)
2. [ML glossary — every term, tied to this project](#2-ml-glossary)
3. [The learning paradigm (supervised binary classification)](#3-the-learning-paradigm)
4. [The model architecture (what "the model" actually is)](#4-the-model-architecture)
5. [How it's trained — concepts behind each step](#5-how-its-trained)
6. [How it classifies a URL at serve time](#6-how-it-classifies)
7. [The percentages — every number, honestly](#7-the-percentages)
8. [WHY XGBoost — and why not each alternative](#8-why-xgboost)
9. [Honest weak spots](#9-honest-weak-spots)
10. [ML-only interview Q&A](#10-ml-only-qa)

---

## 1. The one-paragraph answer

> "The model is a **calibrated XGBoost classifier** — a supervised, binary classifier **trained** on ~1.5 million labelled URLs. Each URL is turned into a feature vector: **22 engineered numeric features** (length, entropy, suspicious-TLD flag, brand-similarity, the `@`-trick, punycode, …) plus **character and word TF-IDF**. XGBoost (gradient-boosted decision trees) learns from those, and a **calibration layer** turns its raw scores into honest probabilities so my 0.60 decision threshold really means '60% likely phishing.' Validated leakage-free with a domain-grouped split, it generalizes at an honest **~74% accuracy** with a **6.23% false-positive rate** on 80,000 legitimate URLs."

Everything below lets you unpack any clause of that paragraph as deep as they push.

---

## 2. ML glossary

Every ML term you might be asked, defined simply **and** tied to PhishGuard. This section *is* "all the terms related to ML."

### The setup
- **Machine learning** — instead of writing explicit rules, you let a model *learn* patterns from examples. → PhishGuard learns "what a phishing URL looks like" from 1.5M examples instead of me hand-coding every rule.
- **Supervised learning** — training on examples that come with the correct answer (a *label*). → every URL is labelled `phishing` or `legitimate`.
- **Unsupervised learning** — no labels; the model finds structure itself (clustering, anomaly detection). → *not* used here; I had labels.
- **Classification** — predicting a *category*. **Regression** — predicting a *number*. → PhishGuard is classification.
- **Binary classification** — exactly two classes. → phishing vs legitimate.
- **Label / target / ground truth** — the known correct answer the model learns to predict. → the `type` column.

### The data representation
- **Feature** — one measurable number describing the input. → "URL length," "number of dots."
- **Feature engineering** — hand-designing features that encode domain knowledge. → my 22 features; each encodes a known phishing signal.
- **Feature vector** — the full list of numbers for one example. → every URL becomes a vector (22 numeric + ~4,000 TF-IDF).
- **TF-IDF** — Term Frequency × Inverse Document Frequency; turns text into numbers, weighting distinctive terms. → char-TF-IDF catches `paypa1`, `g00gle`.
- **n-gram** — a run of n consecutive items. → I use **character** 3-to-5-grams (`pay`, `aypa`, `aypal`).
- **Normalization / standardization** — rescaling features to a common range so none dominates by sheer magnitude. → `StandardScaler` on the 22 numeric features (mean 0, variance 1).
- **Shannon entropy** — a measure of randomness/unpredictability in a string. → feature 5; random-looking hosts (`x7f3q9.com`) score high.
- **Fuzzy matching** — similarity between strings that aren't exactly equal. → `rapidfuzz` compares the host to brand names (`paypa1` ≈ `paypal`).

### Training & evaluation
- **Training set** — data the model learns from. **Validation/calibration set** — data to tune/calibrate on. **Test set** — held-out data to measure honestly. → I use a disjoint 3-way split.
- **Train/test split** — partitioning data so you test on examples the model never trained on.
- **GroupShuffleSplit** — a split that keeps all rows sharing a *group key* on the same side. → group key = registrable domain, so a domain is never in both train and test.
- **Cross-validation** — rotating which slice is held out to get a more stable estimate. → I use `cv="prefit"` for calibration (calibrate on a dedicated held-out slice).
- **Overfitting** — the model memorizes training data and fails on new data. → the symptom of my original leakage; fixed by grouped split + regularization.
- **Underfitting** — the model is too simple to capture the pattern. → why logistic regression alone underperforms here.
- **Bias–variance trade-off** — too-simple models underfit (high bias); too-complex models overfit (high variance). Good models balance both. → XGBoost's depth/learning-rate/regularization tune this balance.
- **Data leakage** — test information secretly influences training, inflating the score. → my headline story: two leaks (domain overlap + path artifact), both fixed. See [master guide §12](INTERVIEW_MASTER_GUIDE.md).
- **Class imbalance** — one class vastly outnumbers the other, so the model can score high by always guessing the majority. → raw feeds are mostly legit; I balance 50/50.
- **Determinism / reproducibility** — same inputs → same model every run. → `random_state=42`, `n_jobs=1`.

### The model internals
- **Parameters** — values the model *learns* (the tree splits). **Hyperparameters** — values *you* set before training (`n_estimators`, `max_depth`, `learning_rate`).
- **Decision tree** — a flowchart of yes/no feature tests ending in a prediction.
- **Ensemble** — combining many models so errors cancel.
- **Bagging** — train many models independently in parallel, average them (→ Random Forest).
- **Boosting** — train models *sequentially*, each fixing the previous ones' mistakes (→ XGBoost).
- **Gradient boosting** — boosting where each new tree fits the *gradient* (steepest-error direction) of the loss function.
- **Regularization** — penalizing complexity to prevent overfitting. → built into XGBoost; a key reason to prefer it.
- **Learning rate** — how much each new tree contributes; smaller = slower but more stable. → `0.05`.
- **Loss function** — the number the model minimizes during training. → `logloss` (log loss / cross-entropy), the standard for probabilistic classification.

### Outputs & metrics
- **Probability output** — the model emits a number 0–1, not just a yes/no. → `model.predict_proba`.
- **Decision threshold** — the cutoff that turns a probability into a verdict. → 0.60 (phishing if prob > 0.60).
- **Calibration** — making the probability *honest* (a "0.7" means ~70% likely). → isotonic calibration.
- **Confusion matrix** — the 2×2 table of correct/incorrect predictions per class.
- **True Positive (TP)** — phishing correctly caught. **False Positive (FP)** — legit wrongly flagged. **True Negative (TN)** — legit correctly passed. **False Negative (FN)** — phishing missed.
- **Precision** — of everything flagged phishing, how much really was = TP / (TP+FP). (High precision = few false alarms.)
- **Recall (sensitivity)** — of all real phishing, how much you caught = TP / (TP+FN). (High recall = few misses.)
- **False-positive rate (FPR)** — of all legit sites, how many you wrongly flagged = FP / (FP+TN). → **my gated metric: 6.23%.**
- **F1 score** — the harmonic mean of precision and recall (one number balancing both).
- **Accuracy** — fraction of all predictions that are correct. → ~74%, but see §7 for why it's not the number that matters most.
- **Precision/recall trade-off** — tightening the threshold raises precision but lowers recall, and vice-versa. → I tune the threshold to control false positives.
- **ROC / AUC** — a threshold-independent summary of how well the model separates the classes.

---

## 3. The learning paradigm

🟢 "Supervised or unsupervised?" is the first ML follow-up. Full answer:

> "**Supervised binary classification.** Every training URL carries a label — phishing or legitimate — so the model learns a mapping from URL features to a known class. The output is a probability between 0 and 1 that the URL is phishing, and a 0.60 threshold converts that to the verdict. I chose supervised because I had abundant *labelled* data and a crisp, two-class target. Unsupervised methods — clustering or anomaly detection — fit when you have no labels or you're hunting unknown attack *types*; here the signal is well-defined and labelled, so supervised learning is both simpler and far more accurate."

**Why binary, not multi-class?** The product question is "is this dangerous or not." SAFE / SUSPICIOUS / PHISHING is a *post-processing* banding of one phishing probability plus the rule gates — not three learned classes. The model itself learns one thing: P(phishing).

---

## 4. The model architecture

🟢 + 🔵. "The model" is actually a small pipeline, not one object. Draw this if you have a whiteboard:

```
          ┌─────────────────────────────────────────────┐
  URL ──► │  FEATURE EXTRACTION                           │
          │   • 22 engineered numeric features (features.py) 
          │   • character TF-IDF  (3–5 grams, 3000 dims)  │
          │   • word TF-IDF       (1000 dims)             │
          └───────────────┬─────────────────────────────┘
                          │  three blocks weighted (0.05, 0.05, 15)
                          │  and stacked  → one sparse vector (~4022 dims)
                          ▼
          ┌─────────────────────────────────────────────┐
          │  XGBoost classifier (400 trees, depth 7)      │  ← learns P(phishing)
          └───────────────┬─────────────────────────────┘
                          │  raw score
                          ▼
          ┌─────────────────────────────────────────────┐
          │  Isotonic calibration layer                   │  ← raw score → honest probability
          └───────────────┬─────────────────────────────┘
                          ▼
                 P(phishing) ∈ [0,1]  ──► threshold 0.60 ──► verdict
```

**The three feature blocks and their weights** `(0.05, 0.05, 15)` = (char-TF-IDF, word-TF-IDF, numeric), applied in **one shared helper** `config.stack_features` used by both training and serving so they can never drift. The numeric block is weighted heaviest on purpose — the engineered features carry most of the decision; TF-IDF is a secondary spelling-look-alike signal.

**The four saved artifacts** (what actually gets pickled): `model.pkl` (the calibrated classifier), `char_vectorizer.pkl`, `word_vectorizer.pkl`, `scaler.pkl`. All four must travel together — serving rebuilds the exact same vector.

**"So is it one model or two?"** 🔵
> "One *base* model — the XGBoost classifier — wrapped in a calibration layer (`CalibratedClassifierCV` with `cv='prefit'`). The base model learns to separate the classes; the calibration layer only remaps its scores to honest probabilities. They're trained on *disjoint* slices so calibration isn't measured on data it saw."

---

## 5. How it's trained

🟢 "trained." The pipeline is `train_ml_strong.py`. Each step with the concept behind it:

| Step | What happens | The ML concept |
|---|---|---|
| 1. Load | combine base + adversarial (×2) + legit + fresh phishing feeds | dataset assembly |
| 2. Clean | drop label noise — phishing on trusted roots, shortener/free-host roots | **label-noise reduction** |
| 3. Balance | sample to 50/50, cap 150k/class | **fixing class imbalance** |
| 4. Augment | emit each URL **bare + pathed**, same path pool for both classes | **de-correlating a leaky feature** (kills "path ⇒ phishing") |
| 5. Strip protocol | remove `http://`/`https://` | removing a cheat signal |
| 6. Split | **GroupShuffleSplit** by registrable domain → disjoint train/calibrate/test | **leakage-free validation** |
| 7. Fit transforms | fit TF-IDF vectorizers + scaler on **train slice only**, transform the rest | **no preprocessing leakage** |
| 8. Train + calibrate | fit XGBoost on train; fit isotonic calibration on the disjoint calibration slice | **training + probability calibration** |
| 9. Save | pickle the 4 artifacts | model serialization |

**The hyperparameters** (`XGBClassifier`) — know every one and *why*:
- `n_estimators=400` — 400 boosting rounds (trees). Enough to learn the pattern; not so many it overfits given the low learning rate.
- `max_depth=7` — each tree can ask up to 7 nested questions, so it can capture interactions like "brand-spoof AND suspicious-TLD" without becoming a memorizing monster.
- `learning_rate=0.05` — each tree contributes only 5%, so the ensemble converges slowly and *stably* (less overfitting than a high rate).
- `scale_pos_weight=1` — no class reweighting, **because I already balanced 50/50**.
- `eval_metric="logloss"` — optimize log loss (cross-entropy), the right loss for probabilistic binary classification.
- `random_state=42`, `n_jobs=1` — **deterministic**: XGBoost's parallel histogram build is otherwise order-nondeterministic, so serial + fixed seed makes a retrain bit-for-bit reproducible. That's what makes the "golden score" regression tests meaningful.

**"Walk me through training in one breath":**
> "Assemble the labelled feeds, clean label noise, balance 50/50, augment to kill the path artifact, split by domain so no domain leaks across train and test, fit the vectorizers and scaler on train only, train 400 gradient-boosted trees, calibrate the probabilities on a disjoint slice, and save. The whole thing is deterministic and gated on not regressing the false-positive ceiling."

---

## 6. How it classifies

🔵 "What happens when a new URL comes in?" (`predict_ml_only.py`)

1. Parse the host; if loopback or a trusted root → short-circuit (SAFE), no model call.
2. Extract the 22 features. If a **structural certainty** fires (raw-IP host, `@`-authority, corroborated brand-spoof) → return phishing with prob 0.999 *without* the model — these are unambiguous.
3. Otherwise, transform the URL: char TF-IDF, word TF-IDF, scaled numeric → `stack_features` with the exact training weights → one sparse vector.
4. `model.predict_proba(X)[0][1]` → the calibrated P(phishing).
5. `pred = int(prob > 0.60)` → the decision.

That `(pred, prob, reason)` then flows into the 6-gate serving ladder in `main.py` ([master guide §14](INTERVIEW_MASTER_GUIDE.md)).

**Key point to say:** "Inference rebuilds the *identical* feature vector the model trained on — same vectorizers, same scaler, same block weights — because all four artifacts are loaded together and the weighting is a single shared function. A train/serve feature mismatch is a classic silent accuracy bug, and the shared helper makes it impossible."

---

## 7. The percentages

🔵 **"How much percentage / what's your accuracy?"** — give the honest number *and* immediately frame why FP rate matters more.

| Metric | Value | How it's measured | What it means |
|---|---|---|---|
| **Grouped hold-out accuracy** | **~74%** | leakage-free, domain-grouped test set | honest generalization to unseen domains |
| **False-positive rate** | **6.23%** | `fp_sweep.py` over 80,110 legit URLs, model-only | legit sites wrongly flagged — **the gated metric** |
| **Cross-source recall** | **~70.4%** | `cross_source_recall_probe.py` on OpenPhish, novel roots only, at 0.60 | phishing caught from a feed never trained on |
| **Homograph probe** | **14/14** | `homograph_probe.py` | look-alike spoofs caught |
| **Retired, inflated** | ~98% | old row-split (leaky) | **never claim — this was the lie I caught** |

### "Why is accuracy only 74% — isn't that low?" 🔵 (handle this confidently)
> "It's low *because it's honest.* The 74% is on a domain-grouped hold-out, so it measures generalization to domains the model has never seen — the hardest, realest test. My first model reported 98%, but that was data leakage: the same domains were in train and test. On a URL-string-only model with no page content, ~74% honest generalization is a *strong* result, and the operational numbers are better than the headline because the real system also uses the blocklist and allowlist."

### "Why don't you lead with accuracy?" 🔵
> "Because accuracy hides the error that actually costs you. In security the expensive mistake is a **false positive** — flagging a real bank as phishing destroys trust instantly. So I gate on the **false-positive rate** (6.23% on 80k legit URLs) and track **recall** separately (~70%). Accuracy treats a missed phish and a false alarm as equally bad; they aren't."

### Confusion-matrix literacy (be ready to define on the spot)
- **False Positive** = legit site flagged as phishing → the costly one → I minimize this (6.23%).
- **False Negative** = phishing missed → caught instead by the live blocklist (defense-in-depth).
- **Precision** = of flagged-phishing, how many were real. **Recall** = of real phishing, how many caught.
- The **threshold (0.60)** is the knob: raise it → fewer false positives, more misses; lower it → more catches, more false alarms. I tuned it to hold the FP ceiling.

### The improvement story (shows engineering discipline) 🔵
> "Across **five gated retrains** (v3.0 → v3.5), the model-only false-positive rate fell from **10.4% to 6.23%**, and recall at an *equal* false-positive rate rose from ~25% to ~61%. Every retrain had to clear a **9.70% false-positive ceiling** or I reverted it, and I compared versions at equal FP — not equal threshold — because a retrain shifts the decision boundary. That's why 'it kept getting better' is a *verifiable* claim, not a vibe."

---

## 8. WHY XGBoost

🟢 The headline "why XGBoost, why not any other" question. Lead with the two-sentence version, then go as deep as they push.

### The two-sentence version
> "My input is ~4,000 sparse TF-IDF dimensions plus 22 dense numeric features, with strong *non-linear interactions* — 'looks like a brand AND has a suspicious TLD' is far more dangerous than either alone. Gradient-boosted trees capture those interactions automatically, train in seconds on a CPU over 1.5M rows, regularize well against overfitting, and are easy to explain — which is why XGBoost beats the alternatives for *this* problem and these constraints."

### The full comparison — why not each alternative

| Model | Why not (for this problem) |
|---|---|
| **Logistic Regression** | Linear — it draws one straight boundary. It **can't capture interactions** ("brand-spoof × suspicious-TLD") without me hand-crafting cross-features. It underfits a problem whose signal is fundamentally about feature *combinations*. |
| **Naive Bayes** | Assumes all features are **independent** given the class. That's flatly false here — length, dot-count, subdomain depth and keyword count are correlated. The independence assumption throws away exactly the interaction signal that matters. |
| **Single Decision Tree** | One tree is a **weak learner** — it either underfits (shallow) or overfits/memorizes (deep). High variance, unstable. Boosting exists precisely to fix this by combining many. |
| **Random Forest (bagging)** | Genuinely good and I considered it. But it builds trees **independently** and averages them, so it reduces variance without directly correcting *systematic* errors. **Boosting** builds trees sequentially, each fixing the previous ones' mistakes, which usually edges out bagging on structured tabular + sparse data like this — at similar cost. |
| **SVM** | Kernel SVMs scale **poorly to ~1.5M rows** (training is roughly quadratic), are slow, and don't produce calibrated probabilities naturally — and I *need* honest probabilities for my thresholds. Linear SVM is just logistic regression's cousin and has the same linearity problem. |
| **k-Nearest Neighbors** | **Lazy** — it does all the work at inference, which is too slow for real-time scanning, and it suffers the **curse of dimensionality** on ~4,000 sparse TF-IDF dims where distance becomes meaningless. |
| **Deep neural net (MLP)** | **Overkill for tabular data.** On structured features, gradient-boosted trees typically **match or beat** MLPs while needing far less data, no GPU, much less tuning, and far less risk of overfitting — and they're **more explainable**, which matters in security and in an interview. |
| **Char-CNN / LSTM / Transformer on raw URL text** | This is a *legitimate* research direction for URLs — I'm honest about that. But it's **heavier**: needs a GPU, more data, careful tuning, slower inference, and a bigger deployment footprint, for **marginal** gains over gradient-boosted trees on engineered features + character TF-IDF. For a CPU-deployed, explainable, portfolio-scale system, the trees are the sweet spot. If this became a product at scale with a GPU budget, a char-level neural model would be the natural next experiment." |

### The honest meta-point (say this — it shows maturity)
> "The honest answer isn't 'neural nets are bad.' It's that **model choice follows constraints.** My constraints were: tabular + sparse features, 1.5M rows, CPU-only, real-time inference, and I had to be able to *explain and gate* every version. Under those constraints, calibrated XGBoost is the best fit. Change the constraints — a GPU budget, raw-text input, a billion rows — and I'd revisit a neural approach."

### "Why calibrated XGBoost and not raw XGBoost?" 🔵
> "Raw XGBoost scores aren't true probabilities, and my whole serving ladder uses *probability* thresholds (0.60 decision, 0.35 safe fast-path). So I wrap it in isotonic calibration so a '0.7' genuinely means ~70% likely phishing. Without that, the thresholds would be arbitrary."

---

## 9. Honest weak spots

Owning these makes you *more* credible, not less:

1. **URL-string only.** No page content, no redirect following, no JS rendering. A brand-new, tell-free domain (`fakebrand123.com`) is a hard ceiling no URL-only model beats — that's what the live blocklist is for.
2. **TF-IDF is secondary** (weight 0.05 vs numeric 15). Don't oversell it. Learning the block weights instead of hand-setting them is documented future work.
3. **~74% accuracy sounds modest** — but it's the *honest* grouped number; the leaky 98% was the lie. Always frame it this way.
4. **The allowlist is a safety net, not the model.** I measure the model *without* it so I always know real model quality.
5. **Snapshot blocklist**, not a live API. Refreshable, but currently a point-in-time snapshot of OpenPhish/PhishTank.

---

## 10. ML-only Q&A

**Q: Supervised or unsupervised, and why?** → §3.
**Q: Binary or multi-class?** → Binary (P(phishing)); the 3 bands are post-processing. §3.
**Q: What is XGBoost?** → trees → ensemble → boosting → gradient boosting → regularized. §2 + §8.
**Q: Why XGBoost over logistic regression / random forest / a neural net?** → §8 table.
**Q: What are your features?** → 22 engineered numeric + char/word TF-IDF; name 6–8. §4, master guide §7.
**Q: What does "calibrated" mean and why do it?** → raw scores → honest probabilities; my thresholds are probabilities. §2, §8.
**Q: How did you avoid overfitting / validate honestly?** → grouped split by domain, disjoint 3-way, fit transforms on train only, regularized trees. §5, master guide §12.
**Q: What's your accuracy?** → ~74% honest + the leakage story + "FP rate is what I gate on." §7.
**Q: Precision vs recall — which do you optimize?** → minimize false positives (6.23% gated); recall ~70% backed by the blocklist. §7.
**Q: How is the probability turned into a verdict?** → threshold 0.60, then the rule gates. §6.
**Q: Why balance the data?** → otherwise the model scores high by always guessing legit; `scale_pos_weight=1` because already balanced. §5.
**Q: Is training reproducible?** → yes — `random_state=42`, `n_jobs=1`, deterministic, golden-score tested. §5.
**Q: What would you try next?** → learned block weights; a char-level neural model with a GPU budget; page-content features; a live blocklist API. §8, §9.

> Lead with the architecture (§4) and the leakage-honest numbers (§7). For "why XGBoost," give the two-sentence version then the constraints meta-point (§8). Every claim here maps to `train_ml_strong.py`, `features.py`, or a named probe.
