# Resume Cheat-Sheet & Interview Defense (verified 2026-09-30)

**Rule of this file:** every line here was checked against the actual code. If it's here, you can
defend it. The "If they ask…" lines are your ready answers — the whole point is that *every keyword
on your resume is one you can go deep on*.

Verified this session: `python -m pytest` → **128 passed**. All metrics traced to
[MODEL_AUDIT.md](../MODEL_AUDIT.md) and the named probe that produced them.

---

## 1. The résumé header line

> **PhishGuard AI — Real-Time Phishing URL Detector**
> Python · FastAPI · XGBoost · scikit-learn · Chrome Extension (MV3) — *Personal project*

---

## 2. The bullets (use 3–4; every number is verified)

**① The model + the API**
> Built a real-time phishing-URL detector using a **calibrated XGBoost** classifier over **22
> engineered URL features + character & word TF-IDF**, served through a **FastAPI** REST API —
> achieving a **6.2% false-positive rate across 80,000 legitimate URLs** and **~70% recall on
> phishing from a live feed it never trained on**.

**② The leakage story (your strongest line)**
> **Diagnosed and fixed data leakage** that had inflated accuracy to a misleading ~98% — re-split the
> data by **registrable domain (GroupShuffleSplit)** and fit all preprocessing on the training slice
> only — reporting an **honest ~74%** generalization accuracy, backed by purpose-built statistical
> probes.

**③ The system design**
> Designed a **model-first, 6-gate detection pipeline** (ML score → structural overrides → known-bad
> blocklist → trusted-domain allowlist → weighted heuristics) that keeps false positives low on real
> brand pages while hard-blocking only structural certainties (raw-IP hosts, `@`-credential URLs,
> homograph brand-spoofs).

**④ The engineering discipline**
> Improved the model across **5 gated retrains** (false positives **10.4% → 6.2%**, recall at equal
> false-positive rate **~25% → 61%**), backing up each model and shipping only if it cleared a **9.7%
> false-positive ceiling**; wrote a **128-case pytest regression suite** plus statistical probes.

**⑤ (optional) Extension + deploy**
> Shipped a **Manifest V3 Chrome extension** that scores every visited page against the same API and
> **fixed two security bugs** in it (a CSP-violating `eval`/`new Function`, and a DOM-XSS `innerHTML`
> sink); deployed full-stack on **Render + Vercel** with SQLite event logging and a **Power BI**
> star-schema export.

---

## 3. Skills line (all honestly backed by this project)

> **ML:** supervised classification, XGBoost/gradient boosting, feature engineering, TF-IDF,
> probability calibration, **data-leakage detection**, precision/recall & FP/recall trade-offs,
> reproducible training. **Backend:** Python, FastAPI, Pydantic, REST. **Data:** dataset assembly
> (~1.5M rows), SQLite, star-schema, Power BI. **Browser:** vanilla JS, Chrome MV3, service workers.
> **Practice:** pytest, regression testing, security hardening, Git, cloud deploy (Render/Vercel).

---

## 4. Defense cheat-sheet — *"if they ask X, say Y"*

### Keyword: **XGBoost / gradient boosting**
- **"What is XGBoost?"** → An ensemble of decision trees built **sequentially by gradient boosting**:
  each new tree fits the *errors* (gradients of the loss) of the trees so far, and predictions are the
  sum of all trees. It adds regularization and handles the sparse mixed feature space well.
- **"Why XGBoost and not logistic regression / a neural net?"** → My input is ~4,000 sparse TF-IDF
  dims + 22 dense numeric features with non-linear interactions (e.g. "brand look-alike **AND**
  suspicious TLD"). Tree boosting captures those interactions without manual feature crosses, trains
  in seconds on 1.5M rows, and needs no GPU. A neural net is overkill for a URL string and harder to
  explain.
- **"Params?"** → `n_estimators=400, max_depth=7, learning_rate=0.05`, plus `random_state` and
  `n_jobs=1` so training is **bit-reproducible**. (In `train_ml_strong.py`.)

### Keyword: **calibrated / calibration**
- **"What does 'calibrated' mean?"** → Raw XGBoost scores aren't true probabilities. I wrap it in
  `CalibratedClassifierCV(method="isotonic")` so a "0.7" really means ~70% likely phishing — which
  matters because my decision threshold (0.60) and the SAFE fast-path (0.35) are probability
  thresholds.
- **"Where is the calibrator fit?"** → On a **disjoint calibration slice**, domain-grouped, separate
  from both train and test — so calibration quality isn't measured on data it saw. (This was a leakage
  fix, audit item C2.)

### Keyword: **22 engineered features**
- **"Name some."** → URL length, count of dots/hyphens/digits, Shannon **entropy** (random-looking
  hosts), keyword count, **fuzzy brand similarity** (catches `paypa1`), brand-spoof flag, **raw-IP
  host**, **`@` in the authority** (credential trick), subdomain depth, suspicious TLD, **punycode
  present**, **non-ASCII host** (homograph). Full list in `features.py`.
- **"Why 22 and why those?"** → Each encodes a known phishing signal a URL string can carry. A locked
  test (`test_features.py`) asserts the vector is always length 22 and pins the meaning of the security
  indices, so a refactor can't silently reorder them.

### Keyword: **TF-IDF (character & word)**
- **"What's it for?"** → Character n-grams (3–5) catch look-alike spellings the numeric features miss
  (`g00gle`, `paypa1`); word TF-IDF catches phishing vocabulary. 3000 char-dims + 1000 word-dims.
- **⚠️ Honest weak spot (know this):** the three feature blocks are combined with weights
  `[0.05, 0.05, 15]`, so the numeric block dominates and TF-IDF contributes modestly. If pushed —
  *"does TF-IDF even matter at 0.05?"* — say: **"It's a secondary signal; the numeric features carry
  most of the decision. Letting the model learn those block weights instead of hand-setting them is a
  documented future improvement (audit item C3)."** Don't oversell TF-IDF as the core.

### Keyword: **data leakage** (your headline — expect the deepest questions here)
- **"What was the leak?"** → Two things. (1) I split by **row**, but one domain has many pathed rows,
  so the *same domain* appeared in train and test — the model memorized domains and the score was
  inflated. (2) A **"URL has a path ⇒ phishing" artifact**: legit examples were mostly bare Tranco
  domains, phishing examples were full URLs with paths, so the model learned "path = phishing."
- **"How did you fix it?"** → (1) **GroupShuffleSplit keyed on the registrable domain**, so a domain is
  entirely in train *or* test, never both — plus a disjoint 3-way train/calibrate/test. (2)
  Path-decorrelation: at training time I emit **every** URL both bare and pathed for **both** classes,
  from the same path pool, so path presence/depth carries no label signal.
- **"Proof it's fixed?"** → `path_artifact_probe.py` — identical domains score the same bare vs pathed;
  `byjus.com` and its deep-path variants are all SAFE at the model level.
- **The line to say:** *"The most valuable thing I did wasn't a high number — it was catching that my
  high number was a lie."*

### Keyword: **GroupShuffleSplit / grouped split**
- **"Why grouped?"** → So evaluation measures **generalization to unseen domains**, not memorization.
  The group key is the registrable domain (`url_augment.registrable_domain`, handles two-part TLDs like
  `co.uk`). Three `assert …isdisjoint()` lines make cross-split leakage a hard failure.

### Keyword: **6.2% false-positive rate / 80,000 URLs**
- **"How measured?"** → `fp_sweep.py` runs the **model alone** (allowlist + rules bypassed) over 80,110
  real legit URLs and counts how many exceed the 0.60 threshold. v3.5 = **6.23%**. It's the **gated
  metric**: a retrain must stay **≤ 9.70%** or I revert it.
- **"Why FP rate, not accuracy?"** → Operationally, flagging a real bank as phishing is the costly
  error. FP rate on legit traffic is the number that actually matters, so I gate on it.

### Keyword: **~70% recall on unseen phishing / cross-source**
- **"What does that mean exactly?"** → `cross_source_recall_probe.py` scores the model on **OpenPhish**,
  a feed it never trained on, counting only **novel registrable roots** (zero overlap) = **70.4%** at
  0.60. Blocklist + allowlist are bypassed so it measures the *model's* lexical generalization, not the
  blocklist trivially matching itself.
- **Honest caveat:** a genuinely tell-free brand-new domain (`fakebrand123.com`) is a **hard ceiling**
  no URL-only model repeals; that's what the live blocklist is for.

### Keyword: **~74% honest accuracy** (NOT 98%)
- **"Your accuracy?"** → *"~74% on a leakage-free, domain-grouped hold-out — and I'll tell you why
  that's the honest number, not the 98% my first split reported."* **Never quote the 98%** as real.

### Keyword: **6-gate pipeline / model-first**
- **"Walk me through it."** → Gate 1: model scores first. Gate 2: structural certainties (raw-IP, `@`
  authority, corroborated brand-spoof) → hard PHISHING. Gate 2b: exact blocklist hit → PHISHING. Gate
  2c: trusted-root allowlist → SAFE. Gate 3: confident-safe fast path (prob < 0.35). Gate 4: weighted
  heuristics + a **dampener** that halves the score when the model is confident-safe. In `main.py`.
- **"Why rules if you have a model?"** → Defense-in-depth. A URL-string model provably can't know a
  specific URL is on a live blocklist, and shouldn't flag `google.com`. The rules handle certainties;
  the model handles the fuzzy middle. **The model runs first — rules are a principled wrapper, not ML
  bolted onto a pile of rules.**

### Keyword: **allowlist / trusted roots**
- **"Isn't an allowlist cheating?"** → It's an FP safety net for ~240 known brands, **exact
  registrable-root match only** (so `dropbox.com.evil.xyz` is *not* trusted). It's **not baked into the
  model** and I measure the model *without* it (that's what `fp_sweep` / the probes do), so I know the
  real model quality behind the net.

### Keyword: **homograph / punycode / IDN — 14/14**
- **"How?"** → `features.py` decodes `xn--` labels and folds confusable Cyrillic/Greek characters to
  their ASCII look-alikes (a "skeleton"), so `xn--pypal-4ve.com` (Cyrillic 'а') matches the brand
  `paypal` and flags — while real `paypal.com` stays SAFE. `homograph_probe.py` = 14/14 (also imported
  by the test suite so probe and test can't diverge).

### Keyword: **128 pytest tests / regression suite**
- **"What do they test?"** → Behavioral **contracts**, each tied to a real past bug: feature vector is
  always length 22; an email in a *query* never fires the `@` rule; a stale blocklist entry can't flip
  `google.com`; `strip_www` is a true-prefix strip; the 14/14 homograph set holds; gate ordering is
  correct. Offline + deterministic, ~8s. They **lock behavior**; the probes own the quality numbers.
- **You can run it on the spot:** `cd backend && python -m pytest` → 128 passed.

### Keyword: **5 gated retrains / 9.7% ceiling**
- **"Explain the process."** → v3.0→v3.5. Before each retrain I back up the model; after, I run
  `fp_sweep.py`; if FP > 9.70% I **revert**. I compare versions at **equal FP** (`operating_point.py`),
  not equal threshold, because a retrain shifts the decision boundary. That's why "it kept getting
  better" is a *verifiable* claim, not a vibe.

### Keyword: **Chrome extension / Manifest V3 / 2 security fixes**
- **"What were the bugs?"** → (1) The MV3 service worker's CSP blocks `eval`/`new Function`, so the old
  banner code never ran — I rebuilt it with `chrome.scripting.executeScript` + `createElement`/
  `textContent`. (2) A **DOM-XSS**: an attacker-controlled URL/reason was rendered via `innerHTML` — I
  switched every injection point to `textContent`. In `extension/background.js` + `popup.js`.

### Keyword: **FastAPI**
- **"Why FastAPI?"** → Async (so a slow WHOIS lookup doesn't block other requests via
  `asyncio.to_thread`), built-in Pydantic validation, auto OpenAPI docs, minimal boilerplate. Overkill
  Django wasn't needed for a few JSON endpoints.

### Keyword: **security hardening** (only if you list it)
- **Parsed-host checks:** host is extracted with `urlsplit` and checked as the real host, **not** a
  substring of the URL — closed a `localhost`-in-the-path bypass. **De-fanging:** `hxxp://`, `[.]` →
  live URL before analysis. **CSV-injection guard:** exported cells starting `= + - @` are quoted so
  Excel can't execute them. **Secrets:** `PHISHTANK_API_KEY` from env, never hardcoded.

### Keyword: **deployed / Render / Vercel**
- **"Is it live / does it have users?"** → Be honest: *"It's deployed and functional as a **portfolio
  project** — FastAPI on Render, static frontend on Vercel — not a product with a user base."* Don't
  imply real users.

---

## 5. Honesty rules (protect yourself)

1. **Never say 98%.** Say ~74% honest + immediately explain the leakage fix. The rigor impresses more
   than a fake number.
2. **It's URL-string-only.** It can't see page content/redirects — say so if asked; that's "future
   work," not a hidden claim.
3. **Datasets are public feeds** (Tranco, OpenPhish, PhishTank, Phishing.Database, Kaggle). Say so.
4. **TF-IDF is a secondary signal** at 0.05 weight — don't present it as the core; the learned block
   weights are a known improvement.
5. **"Deployed" ≠ "has users."** Portfolio project.
6. If you don't know something, say *"that's a documented limitation"* — the audit gives you a real,
   honest answer for every weak spot, which is exactly why this project survives scrutiny.

> Everything above maps to a file, a number, or a reproducible probe. Lead with the leakage story,
> stay honest, go as deep as they want.
