# 07 — Interview Questions & Answers

~80 questions an interviewer could ask about PhishGuard, grouped beginner → hard, each with a
model answer in *your* voice. Answers are grounded in this project's real numbers so you can defend
every claim. **The single most important advice:** when asked about accuracy, **lead with the data-
leakage story** (Q31) — it's the thing that separates you from every candidate who says "I got 98%".

---

## A. Project overview (warm-up)

**Q1. What is PhishGuard in one sentence?**
A real-time phishing-URL detector: you give it a URL, and a calibrated XGBoost model wrapped in a
6-gate rule ladder returns SAFE / SUSPICIOUS / PHISHING with a 0–10 risk score — served by a FastAPI
backend and consumed by a web app and a Chrome extension.

**Q2. Who is it for / what problem does it solve?**
Phishing is the #1 entry point for account compromise. Blocklists alone are always behind — new
phishing domains appear constantly. The goal was a system that **generalizes** to URLs never seen
before (via the model) while still using known-bad and known-good lists where they help.

**Q3. Walk me through what happens when a user checks a URL.**
The frontend sends `POST /predict_url` with the URL. FastAPI validates it with Pydantic, normalizes
it (de-fangs `hxxp`/`[.]`, collapses slashes, caps length), then runs the 6-gate ladder: the model
scores it first, then structural overrides, blocklist, allowlist, a confident-safe fast path, and
finally weighted heuristics for the uncertain middle. The verdict + reasons + score are logged to
SQLite and returned as JSON, which the page renders.

**Q4. What's the tech stack?**
Python 3.12 + FastAPI + uvicorn on the backend; XGBoost + scikit-learn + scipy/numpy for the ML;
SQLite for logging; vanilla HTML/CSS/JS for the frontend; a Manifest V3 Chrome extension; pytest for
tests; Power BI for analytics; deployed on Render (backend) and Vercel (frontend), code on private
GitHub.

**Q5. Why build this instead of using Google Safe Browsing?**
Safe Browsing is a blocklist — excellent for *known* bad URLs, blind to brand-new ones. The point of
this project was to learn and demonstrate an **ML approach that generalizes** to unseen URLs from the
URL string alone, then combine it with blocklist/allowlist knowledge — defense in depth, not one
list.

---

## B. Tech-stack "why this, not that"

**Q6. Why Python?**
The entire ML ecosystem — XGBoost, scikit-learn, scipy — is Python-first, and FastAPI lets the same
language serve the model. No cross-language serialization boundary between training and serving.

**Q7. Why FastAPI over Flask or Django?**
FastAPI gives **async** request handling (so CPU-bound inference runs via `asyncio.to_thread` without
blocking the event loop), **Pydantic** validation for free, and auto-generated OpenAPI docs. Django
is a full web framework — ORM, admin, templates — none of which a JSON prediction API needs. Flask
would work but I'd have to bolt on validation and async myself.

**Q8. Why XGBoost and not logistic regression?**
Logistic regression is linear — it can't capture interactions like "a hyphen-heavy host **and** a
suspicious TLD **and** a brand substring together mean phishing" without manual feature crosses.
XGBoost learns those interactions automatically through decision-tree splits. On this problem the
gap was large and consistent.

**Q9. Why XGBoost and not a random forest?**
A random forest builds independent trees and averages them (bagging). XGBoost builds trees
**sequentially**, each correcting the previous ensemble's errors (boosting), plus L1/L2
regularization and built-in handling of the sparse TF-IDF matrix. For structured/tabular +
sparse-text features it's the stronger, better-regularized model.

**Q10. Why not a deep neural network / LSTM / transformer on the URL characters?**
Three reasons: (1) **data scale and signal** — the discriminative signal here is largely lexical
(tokens, TLDs, brand substrings, character n-grams), which gradient-boosted trees on TF-IDF capture
extremely well; (2) **latency and footprint** — the whole model is a few MB and scores in
milliseconds on CPU, fits a 512 MB free-tier host; a DL model needs far more; (3) **explainability
and calibration** — trees + isotonic calibration give reliable probabilities and I can reason about
feature importance. A transformer would be heavier, slower, harder to calibrate, and wouldn't
clearly beat this on URL strings.

**Q11. Why scikit-learn alongside XGBoost?**
For the pieces around the model: `TfidfVectorizer` (text → sparse vectors), `StandardScaler`
(numeric features), `CalibratedClassifierCV` (isotonic probability calibration), and
`GroupShuffleSplit` (the leakage-free split). XGBoost is the classifier; sklearn is the pipeline.

**Q12. Why SQLite and not PostgreSQL or MongoDB?**
The logging workload is a single-writer append of scan events plus simple reads for the dashboard —
SQLite (in the Python stdlib, zero-config, one file) is exactly right and has **no separate service
to run or pay for**. Postgres would add ops overhead for no benefit at this scale; Mongo's document
model buys nothing for this fixed, relational event schema. If it needed multi-writer concurrency at
scale, I'd move to Postgres — and the schema is simple enough that it'd be a small change.

**Q13. Why vanilla JS and not React?**
The frontend is a few pages with forms and result cards — no complex client state. Vanilla JS means
**no build step, no bundler, no dependency tree**, so Vercel just serves static files and the same
code runs in the extension. React would be over-engineering here.

**Q14. Why a Chrome extension too?**
The web app is pull (you paste a URL); the extension is **push** — it checks every page you navigate
to automatically and warns you *before* you interact. Same backend brain, a more protective UX.

**Q15. Why Power BI / the CSV star schema?**
`export_to_bi.py` turns the SQLite event log into a **star schema** (a fact table + date/type/result
dimensions) so scan trends can be analyzed in Power BI. It demonstrates the analytics/BI side —
turning operational logs into reportable insight — and the `csv_safe` guard even neutralizes CSV
formula injection in the export.

**Q16. Why Render + Vercel?**
Vercel is ideal for zero-config static frontends; Render runs the Python service with a simple
blueprint (`render.yaml`). Both have free tiers, and splitting them means the frontend is on a fast
CDN while the backend scales independently. The tradeoff is Render's free tier **cold-starts**, which
is why the extension uses an 8-second fetch timeout.

---

## C. Machine learning fundamentals

**Q17. Is this supervised or unsupervised?**
**Supervised** — every training URL has a label (phishing=1, legit=0). The model learns the mapping
from labeled examples.

**Q18. Classification or regression?**
**Binary classification.** The model outputs a probability, and thresholds turn it into a class.
(The 0–10 risk score is derived afterward, it's not a regression target.)

**Q19. What are your features?**
Three blocks stacked together: **22 hand-engineered numeric features** (URL length, host length, dot
count, hyphens, digits, has-IP, `@`-in-authority, punycode, non-ASCII host, suspicious TLD,
brand-spoof flag, and so on), a **character TF-IDF** (3–5 grams, 3000 dims — catches
`paypa1`-style obfuscation), and a **word TF-IDF** (1000 dims — catches tokens like `login`,
`verify`, `secure`).

**Q20. What is TF-IDF, in plain terms?**
Term Frequency × Inverse Document Frequency: it weights a token by how often it appears in *this* URL
but down-weights tokens common across *all* URLs. So distinctive tokens (`verify-account`) get more
weight than ubiquitous ones. Character n-grams do the same over 3–5 character slices, which is what
catches look-alike spellings.

**Q21. Why character n-grams *and* word tokens?**
Word tokens catch semantic phishing vocabulary; character n-grams catch **obfuscation** that breaks
word tokenization — `g00gle`, `pаypal` (Cyrillic), `secure-login` mashups. Together they cover both
"what it says" and "how it's spelled".

**Q22. Why StandardScaler on the numeric features?**
It standardizes each numeric feature to mean 0 / variance 1 so no single large-range feature (like
URL length) dominates geometry. Tree models are fairly scale-invariant, but scaling keeps the
numeric block consistent with the pipeline and stable across retrains.

**Q23. You weight the three blocks [0.05, 0.05, 15] — what and why?**
When the char-TFIDF (3000 dims), word-TFIDF (1000 dims), and numeric (22 dims) blocks are stacked,
the sparse text blocks would numerically swamp the 22 dense features. The `FEATURE_WEIGHTS = (0.05,
0.05, 15)` triple rebalances them so the hand-engineered security signals actually carry weight.
It's a tuned constant, locked by a golden-vector test so it can't silently drift.

**Q24. What is calibration and why isotonic?**
Raw classifier scores aren't true probabilities — a "0.9" may not mean 90% likely. Calibration maps
scores to honest probabilities. I used `CalibratedClassifierCV` with **isotonic** regression (a
flexible monotonic fit) so that the 0.35 / 0.55 / 0.60 thresholds mean what they say. This matters
because the whole rule ladder keys off probability bands.

---

## D. XGBoost internals

**Q25. Explain a decision tree.**
A tree asks a sequence of yes/no questions on features ("is dot-count > 4?"), splitting the data to
reduce impurity at each node, until leaves hold a prediction. One tree is interpretable but weak and
prone to overfitting.

**Q26. What is gradient boosting?**
You build trees **sequentially**. Tree 1 makes predictions; you compute the errors (gradients of the
loss); tree 2 is trained to predict those errors; you add it (scaled by the learning rate) to the
ensemble; repeat. Each tree corrects what the ensemble so far got wrong, so a sum of many weak trees
becomes a strong model.

**Q27. What does XGBoost add over plain gradient boosting?**
Second-order (Newton) optimization using gradients *and* Hessians, **L1/L2 regularization** on leaf
weights to fight overfitting, efficient handling of **sparse** matrices (perfect for TF-IDF),
column/row subsampling, and a fast histogram-based split finder.

**Q28. What's the learning rate and why 0.05?**
It scales each tree's contribution. A **small** rate (0.05) means each tree nudges the ensemble
gently, so with enough trees (400) the model converges smoothly and generalizes better than a few
aggressive trees. It's the classic depth-vs-rate-vs-count tradeoff, tuned to stay under the FP gate.

**Q29. Your exact hyperparameters?**
`n_estimators=400, max_depth=7, learning_rate=0.05, scale_pos_weight=1, eval_metric="logloss",
random_state=42, n_jobs=1, verbosity=0`. `max_depth=7` allows meaningful feature interactions
without memorizing; `random_state=42` + `n_jobs=1` make the retrain **deterministic** (reproducible).

**Q30. Why `scale_pos_weight=1` when the data is imbalanced?**
Rather than let XGBoost reweight the positive class (which inflates false positives), I balance at
the **data** level and control the operating point through **thresholds and the FP gate** instead.
Keeping `scale_pos_weight=1` and choosing the threshold from the measured FP/recall curve gave a
cleaner, more controllable false-positive rate than class reweighting did.

---

## E. Data & training (the crux)

**Q31. ⭐ What accuracy did you get? (THE key question — lead with leakage.)**
"Naively, my first models hit ~98% — but I discovered that was **data leakage**, not real skill. Two
leaks: (1) I was splitting **by row**, so different URLs from the *same domain* landed in both train
and test — the model memorized domains instead of learning phishing; and (2) an artifact where almost
every phishing sample had a URL path but many legit samples didn't, so the model learned 'has a path
⇒ phishing'. I fixed the split with **GroupShuffleSplit keyed on the registrable domain** — so a
domain is entirely in train or entirely in test — and balanced the path artifact. Honest accuracy
dropped to about **74–77%**, which is the *real* number. I'd much rather report a defensible 75% than
a fake 98%." **This answer alone will impress most interviewers.**

**Q32. So how do you actually measure the model now?**
Not by a single accuracy number. I use targeted probes: a **false-positive sweep over 80,000 legit
URLs** (the gated metric — must stay ≤ 9.70%, currently **6.23%**), **recall at equal FP** for fair
version-to-version comparison (**61.3%**), and a **cross-source recall** test on an OpenPhish feed
the model **never trained on** (**70.4%** on novel domains). Different questions need different
metrics.

**Q33. What datasets did you use?**
Legit URLs from **Tranco** (top-1M ranked sites) and a large Kaggle legitimate set; phishing from
**OpenPhish**, **PhishTank**, and active phishing-domain feeds. The assembled training set is ~1.5M
rows (~1.35M legit + ~162k phishing), plus held-out sets: 80k legit for the FP sweep and a 5k fresh
holdout for recall.

**Q34. Why those data sources?**
Tranco is a **research-grade, manipulation-resistant** ranking of legit domains — a clean negative
class. OpenPhish/PhishTank are the **standard** live phishing feeds. Mixing multiple phishing sources
reduces source-specific bias, and keeping a **cross-source** feed aside lets me test genuine
generalization rather than memorization.

**Q35. How is the data labeled?**
By source: URLs from phishing feeds are label 1, URLs from legit rankings are label 0. It's
distant/source-labeling — reliable because the feeds are curated, though it inherits any feed noise,
which is one honest limitation.

**Q36. Class imbalance — how did you handle it?**
The raw pool is imbalanced (far more legit). I balanced at the data level for training and, crucially,
control the decision through the **threshold + FP gate** rather than `scale_pos_weight`, because on
this problem false positives (blocking a real bank) are costlier than a missed catch that the
blocklist may still get.

**Q37. Walk me through the training pipeline.**
Load and de-duplicate the sources → compute the registrable domain for grouping → **GroupShuffleSplit**
into train/test by domain → **fit the two TF-IDF vectorizers and the scaler on the TRAIN slice only**
(no peeking at test) → transform both slices → stack the three weighted blocks → train XGBoost →
**isotonic-calibrate** → evaluate with the probes → **only ship if it clears the 9.70% FP gate**,
else revert. Every step is seeded for reproducibility.

**Q38. What's the most important line in that pipeline?**
Fitting the vectorizers and scaler on the **train slice only**. Fitting them on all data before
splitting is a classic, subtle leak — the vocabulary and scaling statistics would carry test
information into training. Doing it after the split is what makes the numbers honest.

**Q39. How did the model improve across retrains?**
Five gated retrains (v3.0 → v3.5). The model-only false-positive rate went **10.37% → 9.70% → 6.39%
→ 6.91% → 6.23%**, and recall-at-equal-FP climbed from ~25% to **61.3%** — so later versions
**dominate** earlier ones (more phishing caught at the *same* false-positive budget, not by trading
one for the other). Every version was backed up first and only kept if it cleared the gate.

**Q40. What exactly changed in the final retrain (v3.5)?**
Two things, both about trust in the number: I moved all vectorizer/scaler fitting to the **train
slice only** (leakage-free), and I made the run **fully deterministic** (`random_state=42`,
`n_jobs=1`). Result: FP improved 6.91% → **6.23%** while recall held/improved, and the homograph set
stayed 14/14 — a strictly better, reproducible model.

---

## F. Detection logic & rules

**Q42. Which runs first — the rules or the model?**
**The model runs first**, at Gate 1 — it scores every URL. The rules then interpret that score:
structural certainties and the blocklist can override upward, the allowlist can clear it, and a
weighted heuristic handles the uncertain middle. It's model-first with a rule safety-net.

**Q43. Then why have rules at all?**
Because a URL-string model has structural blind spots: it can't know a URL was *reported* as live
phishing yesterday (→ blocklist), it shouldn't ever flag `google.com` (→ allowlist), and some attacks
are **certainties** not probabilities — a raw-IP host or an `@`-credential trick is malicious by
construction (→ structural overrides). Rules encode exactly the knowledge the model can't have.

**Q44. Walk through the 6 gates.**
(1) Model scores it. (2) **Structural-critical** (raw IP, `@`-in-authority, or a *corroborated* brand
spoof) → PHISHING 10. (2b) **Blocklist** exact match → PHISHING 9. (2c) **Trusted-root allowlist**
that survived the blocklist → SAFE. (3) **Confident-safe** (prob < 0.35 and no cheap red flags) →
SAFE fast. (4) **Weighted heuristics** combine the probability with brand/typo/subdomain/IP/keyword
signals, apply a confidence dampener, and threshold at 4.5 (PHISHING) / 3.0 (SUSPICIOUS).

**Q45. What's a "corroborated" brand spoof and why corroborate?**
A brand look-alike flag (feat 8) **alone** used to force a hard PHISHING — which nuked legit names
that merely resemble a brand. Now it must be corroborated by a second signal (a suspicious TLD,
punycode, or non-ASCII host) before it's treated as a structural certainty. It cut false positives
without losing real spoofs.

**Q46. Explain the allowlist-vs-blocklist precedence.**
Allowlist normally wins (a trusted root shouldn't be flagged by a stale feed). **The one exception is
shared-hosting commons** — `github.io`, `blogspot.com`, etc. — where trust belongs to the *platform*,
not the *tenant*: `evil.github.io` isn't GitHub, so a blocklist hit there overrides the allowlist.
Real brand roots are deliberately excluded from that carve-out, so a stale entry can never flip
`google.com`.

**Q47. Why is the keyword rule gated on the model probability (≥ 0.55)?**
Otherwise every legit `/login` or `/account` page gets a keyword bump and drifts to SUSPICIOUS.
Requiring the model to already lean phishing (prob ≥ 0.55) before keywords add was a **measured**
trade: −13 phishing caught, +46 legit pages fixed — and every affected case sits in the soft
SUSPICIOUS band, never a hard block.

**Q48. What's the confidence dampener?**
If the model is confidently safe (prob < 0.3), the heuristic score is **halved**, so a couple of weak
structural coincidences on an obviously-safe URL can't add up to a false alarm.

**Q49. How is the 0–10 risk score computed?**
Structural-critical pins it to 10, blocklist to 9, trusted/confident-safe to ~0, and the uncertain
band computes it as `prob×3` plus weighted structural evidence — giving users an intuitive severity
number *and* a defensible verdict.

---

## G. Security engineering

**Q50. Your input is literally hostile URLs — how did you harden parsing?**
Host checks key on the **parsed host**, never URL substrings — so `localhost` in a *path* doesn't
trigger the localhost bypass, and a dotted quad in a path isn't mistaken for an IP host. URLs are
de-fanged (`hxxp`, `[.]`, `[dot]`), length-capped at 2048, and every parser has an exception path
returning a safe default. These are locked by 10 host-parsing tests.

**Q51. What security bugs did you find and fix in the extension?**
Two real ones: (1) the warning banner was built with **`new Function()`**, which MV3's CSP forbids
and is an injection vector — rebuilt with `chrome.scripting.executeScript` + `createElement`/
`textContent`; (2) a **DOM-XSS** surface from rendering attacker-controlled URLs via `innerHTML` —
switched everything to `textContent`. Essential, since every input to this tool is a hostile URL.

**Q52. CSV formula injection — what's that and where does it apply?**
When you export data to CSV and a field starts with `=`, `+`, `-`, or `@`, spreadsheet apps may
**execute it as a formula**. My Power BI export runs every field through a `csv_safe` guard that
neutralizes those leading characters, so a malicious URL in the log can't become a live formula in
Excel.

**Q53. How do you handle secrets / API keys?**
Never hardcoded — the PhishTank key and DB path come from **environment variables**, with graceful
degradation if absent (the app catches `FileNotFoundError` and runs without the optional feed). The
repo is private and secret-scanned before every push.

**Q54. Is there rate limiting / abuse protection?**
The optional WHOIS/SSL enrichment has timeouts (4 s / 5 s) and a 900 s cache; the extension bounds
its own cache (200 entries / 60 s) and times out backend calls at 8 s. For a production deployment
I'd add per-IP rate limiting at the API gateway — I'd call that a known next step rather than claim
it's done.

---

## H. Architecture & systems

**Q55. Why is inference wrapped in `asyncio.to_thread`?**
Model scoring is **CPU-bound and synchronous**. Awaiting it directly would block FastAPI's event
loop and stall other requests. `asyncio.to_thread` offloads it to a thread so the server stays
responsive.

**Q56. How does the model get loaded — per request?**
No — artifacts (the XGBoost model, both vectorizers, the scaler) are loaded **once at process start**
and reused, `__file__`-anchored so paths work regardless of the working directory. Per-request load
would be far too slow.

**Q57. What are the API endpoints?**
`POST /predict_url` (the core check), a `/health` endpoint (Render's health check), and
dashboard/stats reads that serve the logged history. All JSON.

**Q58. How is scan history stored and shown?**
Every verdict is appended to a SQLite `phishing_events` table (URL, verdict, score, reasons,
timestamp). The dashboard reads aggregates from it, and `export_to_bi.py` turns it into a Power BI
star schema.

**Q59. One detection brain, three clients — explain.**
The checker page, the dashboard, and the Chrome extension **all call the same `/predict_url`**. There's
exactly one place the detection logic lives (the FastAPI ladder), so behavior is consistent
everywhere and there's no duplicated logic to drift.

**Q60. What happens on the Render free-tier cold start?**
After inactivity the backend sleeps and the first request takes seconds to wake it. Clients handle it
gracefully — the extension's 8 s timeout and the frontend's loading state — and I documented it. For
always-on I'd move to a paid tier or a small keep-warm ping.

---

## I. Testing

**Q61. How did you test this?**
Two layers. **128 offline pytest cases** lock behavioral contracts — deterministic, no network — each
tied to a real bug (feature vector length 22, `@`-in-query must *not* fire the rule, a stale
blocklist entry must never flip a real brand). Separately, **statistical probes** own the quality
numbers (the 80k FP sweep, equal-FP recall, cross-source recall).

**Q62. What does "regression testing" mean in this project?**
Guarding against **re-breaking** a fixed bug. Before, the "tests" were print-only scripts with no
assertions — nothing caught a regression. The pytest suite asserts the contracts loudly, so a future
edit or retrain that undoes the byjus path fix or the homograph set fails CI immediately.

**Q63. Why separate unit tests from the quality metrics?**
A green unit test doesn't prove the model is *accurate*, and a good accuracy number doesn't prove an
edit didn't break the `@`-rule. You need both: fast contracts that can't regress, and large-scale
metrics that measure quality. The pytest suite touches no model artifact, so it can't even affect the
FP gate.

**Q64. What's the most important single test?**
The **golden feature-vector + golden-score** test. It pins an exact 22-length vector and the model's
score on known inputs, so any drift in features, weights, or the model itself trips it and forces a
conscious re-baseline through the FP gate — nothing changes silently.

---

## J. Hard / senior-level

**Q65. What are this project's real limitations?**
(1) It's **URL-string only** — it never fetches page content, so it misses phishing that looks benign
in the URL but malicious on the page. (2) Labels are **source-distant**, inheriting feed noise. (3)
Honest accuracy is ~75%, not 98% — the model is one layer, not a silver bullet. (4) No page-render or
screenshot analysis. I'm clear about all of these; the layered design is precisely because the model
alone isn't enough.

**Q66. How would you handle concept drift as phishing evolves?**
The blocklist already updates from live feeds. For the model I'd schedule **periodic gated retrains**
on fresh feeds (the pipeline is deterministic and gated, so this is safe to automate), monitor the FP
sweep and cross-source recall over time, and alert if either degrades — retrain triggered by drift,
not the calendar.

**Q67. If you had to cut the false-positive rate in half, what would you do?**
First look at *which* legit URLs the 6.23% sweep flags and find the shared structure. Likely levers:
expand the allowlist for the common offenders, add corroboration requirements to whichever heuristic
is over-firing, and ret(train) with those hard negatives up-weighted — then re-run the equal-FP
recall to make sure I'm not just trading recall away. Measure, don't guess.

**Q68. How would you add page-content analysis without wrecking latency?**
Keep the URL model as the fast synchronous path (milliseconds), and add content fetching as an
**optional async enrichment** behind a timeout — the way WHOIS/SSL already work. The verdict returns
immediately on the URL signal and can be upgraded if the fetch completes in budget. Never block the
core path on a network fetch of a hostile page.

**Q69. Your accuracy is 75% — isn't that too low to be useful?**
Not in context. Accuracy is the wrong single lens — what matters operationally is a **low false-
positive rate** (6.23%, so it rarely cries wolf on real sites) combined with **strong recall on novel
phishing** (70.4% cross-source) *and* the blocklist catching known-bad on top. The model is the
generalizing layer of a defense-in-depth system, not the whole defense.

**Q70. How do you know your 70.4% cross-source recall isn't also leakage?**
Because that probe scores URLs from an OpenPhish feed with **novel registrable domains the model
never trained on**, and it **bypasses the blocklist and allowlist** so it can't just be matching known
entries — it isolates what the *model* learned lexically. It even re-scores the same-feed holdout in
the same run as an anchor and reproduces that number exactly, validating the scorer.

**Q71. Why calibrate if you only threshold the probability?**
Because the thresholds (0.35, 0.55, 0.60) are meaningful **bands**, and the keyword gate compares
against 0.55. If the probabilities were uncalibrated, those cut-points would be arbitrary. Isotonic
calibration makes "0.6" actually mean roughly 60% likelihood, so the whole ladder's logic is sound.

**Q72. Defend `max_depth=7` specifically.**
Depth 7 allows up to seven-way feature interactions — enough to combine signals like
TLD + brand-substring + host-length, which is where phishing structure lives — while staying shallow
enough (with `learning_rate=0.05` over 400 trees and L1/L2) to not memorize individual domains. I
confirmed it holds the FP gate; deeper trees raised FP without a recall payoff.

**Q73. What would break first at 100× traffic?**
The single-writer **SQLite** log and the single Render instance. I'd move logging to Postgres (or
batch/queue writes), run multiple stateless API replicas behind a load balancer (the model is
read-only in memory, so it scales horizontally cleanly), and put the blocklist in a shared cache.
The model inference itself is cheap and parallelizes trivially.

**Q74. Is there any train/serve skew risk?**
The main risk is feature computation differing between training and serving. I mitigate it by using
the **same feature code path** and locking the `FEATURE_WEIGHTS` and a golden vector in tests, so the
serving vector provably matches what the model was trained on. The probes also use the exact serving
weights, so their numbers are like-for-like with production.

**Q75. If the model and the blocklist disagree, who wins and why?**
Depends on direction. Blocklist-says-bad **overrides** a model-says-safe (Gate 2b runs before the
confident-safe path) because a *reported live* phishing URL is ground truth the model can't have.
Allowlist-says-good overrides a stale blocklist entry (except shared-hosting). The precedence encodes
which source is more trustworthy *for that case*.

**Q76. What's the one thing you're proudest of, technically?**
Catching my own data leakage and choosing to report the honest ~75% over the fake 98%. It's the
difference between a demo and an engineering artifact — and everything downstream (the probes, the FP
gate, the leakage-free retrain) came from taking that seriously.

**Q77. What would you do differently if you started over?**
Set up the **GroupShuffleSplit and the FP gate on day one**, before ever looking at an accuracy
number — so I'd never have been tempted by the leaked 98%. And I'd wire the pytest suite in from the
start instead of after the print-scripts, so every change was gated from commit one.

**Q78. How is this deployed and kept reproducible?**
Backend on Render via `render.yaml` (Python 3.12.1 pinned, uvicorn, `/health` check), frontend on
Vercel (static, `vercel.json`), code on private GitHub. The model artifacts are committed so a fresh
clone runs, the training run is deterministic (seeded, `n_jobs=1`), and `MODEL_AUDIT.md` records the
exact metric for every version.

**Q79. Explain this project to a non-technical person.**
It's a tool that looks at a web link and tells you if it's a scam — like a spam filter for links. It
learned what scam links tend to look like from millions of examples, and it also keeps a list of
links known to be dangerous and a list of sites known to be safe. It runs in a website and as a
browser add-on that warns you automatically.

**Q80. Where does this go next?**
Page-content analysis as async enrichment, automated drift-triggered retrains, per-IP rate limiting,
and publishing the extension to the Chrome Web Store. But I'd keep the core principle: a fast,
explainable, model-first detector with a rule safety-net, and every model change gated on the false-
positive ceiling.

---

## How to use this doc

- **Memorize Q31 (leakage) and Q42 (model-first) cold** — they're the two you're most likely to be
  asked and the two that most impress.
- For any "why X not Y" question, the pattern is: *what X gives → what Y costs → why it matters here.*
- When you don't know something, do what Q54/Q65 model: **state the honest limitation and the next
  step.** Interviewers trust that far more than bluffing.

Next: [08_RESUME_POINTS.md](08_RESUME_POINTS.md) — exact resume bullets and the "tell me about a
project" script.
