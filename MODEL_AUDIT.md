# PhishGuard AI — Model & System Limitations Audit

_Audit date: 2026-09-22. Scope: the full URL-detection pipeline
(features.py, train_ml_strong.py, predict_ml_only.py, main.py, the three
dataset builders, config.py). Every finding below is grounded in the code or
in a reproducible test (see `backend/model_stress_test.py`,
`backend/path_artifact_probe.py`, `backend/probe_model.py`,
`backend/explain_decision.py`)._

Severity: **P0** = breaks real-world accuracy now · **P1** = significant ·
**P2** = hardening / good practice.

---

## ✅ P0 execution status — 2026-09-22 (retrained model v3.0)

All three P0 items are **DONE** and measured. Backups of the previous model are
preserved at `backend/model_backup_20260922_171304/` and
`backend/model_backup_pre_retrain/`.

**P0.1 — Path artifact killed (A1, A2, A3, A4).**
Retrained with train-time path decorrelation (every URL emitted bare **and**
pathed, same `PATH_POOL` for both classes → path presence/content carry no class
signal) plus a broadened, decoupled phishing vocabulary (53 brands / 43 keywords,
no longer the 13/12 feature words) and bare phishing hosts.
- _Before:_ `byjus.com` 0.004 SAFE → `byjus.com/home` **0.999 PHISHING**.
- _After:_ `byjus.com` 0.126 → `/home` 0.268 → `/products/item/123` 0.391 — **all
  SAFE**; all 6 probe domains hold SAFE across every path variant
  (`path_artifact_probe.py`).
- _Before:_ `amazon-refund-claim-now.online` 0.044 SAFE (missed — "refund/claim"
  not in vocab). _After:_ **0.999 PHISHING**; obvious-phishing set now 8/8 caught.
- Realistic model-only mix (`model_stress_test.py`): **65.0% → 67.5%**; the
  path-driven false positives `zomato.com/bangalore` (was 0.999) and
  `practo.com/doctors` (was 1.000) are now **SAFE** (0.336).

**P0.2 — `@` credential-trick scoped to the authority (B1).**
`features.py` feat 11/12 now test the netloc only.
- _Before:_ `mystore.in/contact?email=help@mystore.in` → forced **PHISHING 10.0**.
- _After:_ feats[11]=0, structural rule does **not** fire (`reason=None`); the
  genuine trick `legit.com@evil.com` still forces PHISHING 0.999.

**P0.3 — Honest, leakage-free evaluation (C1, C2, C5).**
Replaced the row-level `train_test_split` with **GroupShuffleSplit by registrable
domain** and a **disjoint 3-way train/calibrate/test** split (calibration no
longer fit on the eval set).
- _Before:_ "~98%" — inflated by domain leakage; calibration fit on the test set.
- _After (honest):_ **77% accuracy** on 13,696 held-out domains never seen in
  training; legit recall 0.91, phishing precision 0.83. This is a real
  generalization estimate, not a leaked one.

**What the honest numbers now expose (→ P1 work):** the model's remaining errors
are the *inherent* limits of URL-string-only detection — hyphenated legit domains
(`union-bank-of-india.co.in`, `secure-banking-login.hdfc.in`) still false-positive
(covered by the allowlist in production; needs non-lexical signals + brand
corroboration), and clean bare phishing (`mybankportal.in`, `accountsverify.com`)
still slips — though these now score **0.27–0.34** (just under the 0.50 line, up
from ~0.01 before), so threshold tuning + domain-age/reputation features (P1
C4/A4/B4) should recover several. The path/vocabulary *artifacts* are gone; what
remains is the honest hard core of the problem.

---

## ✅ P1 execution status — 2026-09-23 (retrained model v3.1 + runtime hardening)

The high-value P1 batch is **DONE** and measured. The v3.0 model was backed up to
`backend/model_backup_v30_pre_p1_20260922_181010/` before the v3.1 retrain.
Everything below is reproducible via `backend/model_stress_test.py`,
`backend/homograph_probe.py`, and `backend/path_artifact_probe.py`.

**B2 — Brand / keyword / TLD lists expanded.**
brands 13 → 32, keywords 12 → 41, suspicious TLDs 9 → 19 (all in `rules.json`,
so `features.py` and every consumer pick them up with no code change). New brands
are a subset of `generate_adversarial.py`'s 53 so the model trains on them; all
≥5 chars to avoid trivial substring collisions.

**B3 — Punycode / IDN homograph handling added.**
`features.py` now decodes each `xn--` label (`_decode_idn`) and maps
confusable/Cyrillic/Greek look-alikes to their ASCII twins (`_skeleton` +
`_CONFUSABLES`), unioning the skeleton into the brand fuzzy match so a homograph
fires feat 8. Two new features: feat 20 = punycode label present, feat 21 =
non-ASCII host after decode (feature count 20 → 22). Skeleton of pure-ASCII is
identity, so legit ASCII hosts are unchanged (no regression).
- `xn--pypal-4ve.com` (Cyrillic-a "paypal") → feat7=1.00, feat8=1, feat20=1,
  feat21=1 → **PHISHING**; real `paypal.com` → feat8=0 (domain==brand) → SAFE.
- `homograph_probe.py`: **14/14** (4 punycode spoofs + 5 ASCII typosquats caught,
  5 real-brand/legit controls not flagged).

**D2 — SSL de-weighted; SAFE verdict made deterministic.**
Gate 3's SAFE fast path no longer depends on flaky live SSL. It now gates on
cheap, deterministic **local** structural flags (typo-squat / brand-in-subdomain
/ brand-in-domain); SSL is skipped and reported as `null` ("not checked"),
mirroring how domain age already reports `-1` → "Unknown". Verified end-to-end:
`byjus.com` → SAFE with `ssl_valid: null` on every run (live backend + the
frontend display expressions render "SSL valid: Not checked").

**D4 — Brand-spoof override now requires corroboration.**
A feat-8 fuzzy brand match alone no longer forces PHISHING 0.999 — it must be
corroborated by a phishing keyword (feat 9), a suspicious TLD (feat 16), or an
IDN/homograph host (feat 20/21); otherwise it falls through to the soft model
score. Raw IP (feat 10) and the credential-hiding `@` (feat 11) still fire
unconditionally. A bare typosquat with no corroboration (`paypa1.com`) is still
caught downstream via the Gate-3 → Gate-4 typo heuristic (verified: PHISHING
4.84), so closing the override did **not** open a false-negative hole.

**D5 — Input hardening / de-fanging.**
`main.py._normalize_url` converts defanged threat-intel notation back to a live
URL (`hxxp://`→`http://`, `[.]`/`[dot]`/`(.)`→`.`, stray-bracket strip), caps
input at 2048 chars, and CORS is now env-configurable (`CORS_ORIGINS`, defaults
`*` for the local demo). Verified: `hxxp://evil[.]com` → analyzed as
`http://evil.com` end-to-end.

**C4 — Decision threshold made configurable; kept at 0.50 (measured decision).**
Added `ML_DECISION_THRESHOLD` (rules.json → config.py → predict_ml). Tuning it
**down** was evaluated and rejected: the Section-D bare-phishing false negatives
score 0.25–0.34, which overlaps the Section-A/B hyphenated-legit scores
0.30–0.41, so lowering the line catches a few more phish at the cost of *more*
legit false positives. 0.50 stays until a non-lexical signal separates those
clusters. _(Superseded 2026-09-24: the v3.3 fresh-data retrain moved the FP/recall
frontier enough that raising the line **up** to 0.60 now cuts FP (9.70% → 6.39%) AND
keeps a doubled recall — the opposite tradeoff to what the v3.1 data allowed. See the
v3.3 status block + `operating_point.py`. `ML_DECISION_THRESHOLD` is now 0.60.)_

**Net measured effect (`model_stress_test.py`, rules bypassed):**
model-only accuracy **67.5% → 72.5%** (11 errors vs 13); legit false positives
**1580 → 1314** (~17% fewer). Path artifact stays dead (all 6 probe domains SAFE
across every path variant); obvious-phishing set **8/8 @ 1.000**.

**Deliberately NOT done (kept honest):** B4 (fold domain-age/cert-age into the
**model**) remains a runtime-gate signal only — offline training rows have no
reliable age, so training on it would just teach a new "age unknown ⇒ phishing"
artifact. A5 (Tranco label-noise filtering), A4 (harvest real clean bare
phishing), and D1 (live PhishTank feed) are untouched this batch. These are the
remaining honest limits, not regressions.

---

## ✅ P2 execution status — 2026-09-24 (retrained model v3.2b + byjus path fix + live feed)

The remaining P2/data-quality batch is **DONE** and measured. The v3.1 model was
backed up to `backend/model_backup_v31_pre_p2_20260923_085611/` before the retrain,
and the finalized v3.2b artifacts are snapshotted at
`backend/model_backup_v32b_20260924/`. Everything below is reproducible via
`backend/fp_sweep.py` (an 80,110-URL model-only legit sweep — the reproducible
false-positive metric), `backend/byjus_pathfix_probe.py`, `backend/homograph_probe.py`,
`backend/path_artifact_probe.py`, and `backend/model_stress_test.py`.

**A5 — Host-level label-noise filtering (two surgical rules).**
`train_ml_strong.py` now drops, BEFORE balancing:
(a) phishing rows whose registrable root is a curated `trusted_roots` domain
(15,011 rows — a feed attaching a phishing path to `byjus.com`/`sbi.co.in` must
never become a phishing *training* example), and
(b) shortener / free-host roots from **both** classes (8,970 legit + 13,477
phishing — a root like `bit.ly`/`github.io` is shared by thousands of unrelated
sites, so "root ⇒ class" is pure noise there).
A third, more aggressive rule (c) — drop every phishing row whose root appears
anywhere in the legit set — was **tried and reverted**: it stripped out
legit-host-but-compromised phishing (real "clean host + phishing path" data),
shifting the phishing class toward hyphen/keyword hostnames and pushing the
model-only legit false-positive rate **up** 10.4% → 13.8% on the 80k sweep, with
the new FPs overwhelmingly clean-host + security-path URLs
(`channel4.com/account`, `indiatoday.in/secure/checkout`) — i.e. it made the path
artifact *worse*. Rules (a)+(b) remove the unambiguous noise; the byjus-class
clean roots are protected by the `trusted_roots` allowlist at serving time, so
(c) is unnecessary. GroupShuffleSplit already prevents any root leaking across
splits.

**byjus.com path false-positive — fixed at three layers.**
The reported bug (`https://byjus.com` SAFE, but `byjus.com` with a deep/many-slash
path crept toward PHISHING) is closed by:
1. _Model_ — deep-path decorrelation in `url_augment.add_path` (deep,
   keyword-stacked paths emitted for **both** classes at train time, so path
   depth/keyword-stacking carries no label signal). `byjus_pathfix_probe.py`:
   every variant SAFE, worst model_prob **0.4530** (was 0.5313 in v3.2, was 0.999
   in v2.1) — the host decides, not the path depth.
2. _Runtime_ — `main.py._normalize_url` collapses runs of redundant slashes
   (`(?<!:)/{2,}` → `/`, preserving `://`), so `byjus.com//////login` can't
   inflate features.
3. _Allowlist_ — `byjus.com` (+ `byjusexamprep.com`) added to `trusted_roots`
   (243 → 245): the "parent-root consideration" safety net — SAFE in production
   regardless of model score. (Confirmed byjus appears ONLY as legitimate in every
   dataset, so this was a pure generalization gap, never label noise.)

**D1 — Dead PhishTank feed replaced with a local blocklist.**
The old `check_phishtank` POSTed to a deprecated `http://` endpoint (always
returned False). It's replaced by `_load_local_blocklist()`, which loads
`data/raw/openphish.txt` + `phishtank.csv` into a frozenset at startup and does an
exact normalized-URL membership test (`RAW_FEED_DIR` env-configurable). No live
network dependency in the hot path; `import requests` removed.

**B4 investigated & rejected + fresh-feed refresh added (2026-09-24).** After
finalizing v3.2b, the user-selected next phase was B4 (fold non-lexical signals
into the model). Built `backend/b4_signal_probe.py` and measured LIVE WHOIS/DNS/
cert age on a fresh 100+100 sample. Result: domain age does **not** separate the
classes (median live age: phishing 14.5 yr vs legit 13.3 yr; only 8% of live
phishing is <1 yr old vs legit's 10%); the sole separator is "domain still
resolves," a **takedown artifact** of the April-2025 snapshot that would teach
"unreachable ⇒ phishing" and fire on any temporarily-down legit site. B4 is
therefore **rejected on evidence** (full table in §B4). The probe pinpointed the
real root cause — **stale data** — so the shipped fix is a refresh path, not a
model change: `backend/refresh_feeds.py` pulls the LIVE OpenPhish community feed
(free; PhishTank too if `PHISHTANK_API_KEY` is set) and **unions** fresh
currently-live URLs into `data/raw/openphish.txt` (timestamped backup + atomic
write; network failure leaves the file untouched). First run added **300 fresh
URLs, 0 overlap** with April — proving total staleness — and after a restart the
backend flags them (verified E2E: `zesty-poppy-120.harvis.page`,
`roblox.com.do/...` → PHISHING via blocklist; `google.com`/`byjus.com` still
SAFE). This is pure additive detection: it touches no model artifact, so the
9.70% FP gate is structurally unregressed. Re-runnable from cron to accumulate a
fresh corpus — the prerequisite for ever revisiting A4/B4 with live data.

**Net measured effect (finalized v3.2b vs the v3.1 backup, identical URL sets):**
| Metric | v3.1 | v3.2b | Δ |
|---|---|---|---|
| 80k legit FP sweep, model-only (`fp_sweep.py`) | 8,306 / **10.37%** | 7,767 / **9.70%** | **−539 FPs (−6.5% rel)** |
| Homograph/IDN probe | 14/14 | **14/14** | held |
| byjus deep-path (worst model_prob) | — | **0.4530, all SAFE** | artifact dead |
| Path-artifact probe (6 domains) | pass | **pass** | held |
| Stress-test model-only accuracy | 72.5% | **72.5%** | held |

Notably v3.1's worst-FP list flagged `secure.paypal.com/signin` and
`account.microsoft.com/` at model_prob **1.000**; v3.2b no longer does — it
generalizes better on real brand roots, not just allowlisted ones. v3.2b is
**at-or-better than v3.1 on every measured axis** and is the live model.

**Deliberately NOT done (kept honest):** B4 (fold domain-age/cert-age into the
**model**) — as of 2026-09-24 this is no longer just deferred, it is **rejected on
live evidence** (`b4_signal_probe.py`): among phishing domains still alive, age is
statistically indistinguishable from legit (median 14.5 yr vs 13.3 yr; only 8%
fresh vs legit's 10%), and the sole class separator is "still resolves," a
takedown artifact that would teach "unreachable ⇒ phishing." See the B4 entry in
§B for the table. A4 (harvest real clean bare phishing) and C3/C6 (learn feature
scales / grouped CV) remain the honest next items — and both, like B4, ultimately
need a **fresh live-phishing data source**, which is now the identified root
cause. These are documented limits, not regressions.

---

## ✅ Regression test suite added — 2026-09-24 (`backend/tests/`, pytest, offline)

**Why.** Until now the only "tests" were print-only scripts (`test_ml_only.py`,
the probes) with **no assertions** — see §C5. Nothing mechanically caught a
regression, so a future edit or retrain could silently reintroduce the byjus
path false-positive, break the 14/14 homograph set, change the 22-length feature
vector, un-scope the `@`-credential check back to the whole URL, or re-break the
D1 blocklist loader — with green-looking output the whole time. This adds a
real, one-command safety net.

**What.** 59 deterministic, fully **offline** tests (no network, no retrain) under
`backend/tests/`. `conftest.py` `chdir`s to `backend/` (the model artifacts and
`../data/raw` load cwd-relative) and puts it on `sys.path`. Six modules lock:
* **test_features.py** — `extract_features()` is always length **22**; exact
  meaning of the security indices: IP (feat 10), `@`-in-**authority-only** (feat
  11, and an email in the query does *not* fire), punycode (feat 20), non-ASCII
  host (feat 21), suspicious TLD (feat 16), brand-spoof (feat 8, incl. the
  `g00gle` look-alike, and `google.com` root is *not* a spoof).
* **test_config.py** — `trusted_roots` is a lowercase set (>100) containing
  `google.com`/`byjus.com`/`byjusexamprep.com`; `ML_DECISION_THRESHOLD == 0.5`;
  `ML_SAFE < ML_DECISION`; `T_SUSPICIOUS < T_PHISHING`; `strip_www` true-prefix
  strip (`www.whatsapp.com` → `whatsapp.com`, not `hatsapp.com`).
* **test_url_augment.py** — `registrable_domain` incl. two-part TLDs
  (`a.b.co.uk` → `b.co.uk`) and `@`/port stripping; `has_path`; `add_path`
  determinism under a seeded RNG.
* **test_main_helpers.py** — `_normalize_url` de-fangs (`hxxp`, `[.]`, `[dot]`)
  and collapses redundant slashes (`byjus.com//////login` → `.../login`) while
  preserving `://`, plus the 2048 cap; `extract_domain` `@`/port/www stripping;
  `levenshtein`; `check_typo`/`check_subdomain`.
* **test_model_invariants.py** — end-to-end `predict_ml`: trusted roots +
  localhost never flagged; raw-IP and `@`-credential force PHISHING; the **full
  14-case** homograph+typosquat+control set stays **14/14**; and the byjus
  deep-path artifact stays **below the 0.5 decision threshold at the model level**
  (defense in depth beyond the allowlist). It imports `CASES` and the
  serving-weight `model_only()` **directly from `homograph_probe.py`**, so the
  suite and the probe can never silently diverge.
* **test_blocklist.py** — the D1 loader populates a `frozenset` (>1000 entries)
  and `check_phishtank` matches a known entry (and its trailing-slash form) but
  not an arbitrary URL.

**Run.** `cd backend && python -m pytest` → **59 passed in ~9 s**. `pytest==9.1.1`
added to `requirements.txt` under a test/dev section. Because the suite touches
no model artifact and makes no network call, it can gate every future change and
**cannot** regress the 9.70% FP gate. It does not replace the statistical probes
(`fp_sweep.py`, `model_stress_test.py`) — those still own the model-quality
numbers §C5 asks for; the suite locks the *behavioural contracts* around them.

---

## ✅ v3.3 — Fresh-data retrain (2026-09-24, model v3.3, backend v2.7 @ threshold 0.6)

**Why.** The user named the two honest limits that survived v3.2b and asked to fix
them *with more real data, not more rules*: (1) the model-only legit **false-positive
rate was 9.70%** on the 80k sweep, and (2) **clean bare-domain phishing** (a brand-new
`fakebrand123.com` with no path, no `@`, no IP, valid HTTPS, no keywords) slipped
through — a URL-only model's hard case. Both need *fresh real phishing signal*, which
§A4/§B4 had already identified as the true root cause.

**Data acquired (free, no upload needed).** `backend/harvest_fresh_data.py` (new,
reproducible) pulls the **Phishing.Database `ACTIVE`** list (391,986 currently-live
domains), keeps only rows that are **NOVEL** (registrable root not already in the
phishing corpus) **and CLEAN** (root not in the legit set, not in `trusted_roots`, not
a shortener/free-host `NOISE_ROOT`) → **159,797** usable fresh phishing roots. A seeded
(SEED=42) split reserves **5,000 as an unseen holdout** (`fresh_holdout.csv`) and writes
the rest to `fresh_phishing.csv` as bare `http://<root>` rows (so they train the
*bare-domain* class the model was weakest on). The trainer re-applies its own
label-noise rules authoritatively; the harvester never imports the trainer.

**Retrain.** `train_ml_strong.py`: `MAX_PER_CLASS` raised **50k → 150k** (×2 after
bare+pathed augmentation ≈ 300k/class); `fresh_phishing.csv` loaded after the
adversarial set, before legit. Everything else held: 22 features, the
`hstack([Xc*0.05, Xw*0.05, Xn*15])` serving weights, A5 label-noise cleaning,
path-decorrelation augmentation, GroupShuffleSplit by registrable domain (disjoint
train/cal/test). v3.2b artifacts backed up to
`backend/model_backup_v33_pre_freshdata_20260924/` (the revert target) before training.

**The frontier moved — so the threshold moved (0.5 → 0.6).** A retrain that adds
aggressive fresh phishing shifts the decision boundary: at a *fixed* 0.5 the new model
flags more (FP rose to 12.00%, recall to 65.4%). Comparing two models at one threshold
is therefore misleading — the fair test is **recall at equal FP**. `operating_point.py`
(new) scores legit FP and holdout recall across thresholds for any model dir and finds
the threshold pinning FP to the v3.2b 9.70% gate:

```
  thr    FP%     recall%      (v3.3, model-only)
  0.50   12.00    65.4
  0.55    8.32    59.3
  0.60    6.39    54.9   <- shipped
  0.65    4.50    50.1
  gate: thr 0.530 -> FP 9.19%  recall 61.1%   (v3.2b was FP 9.70% recall 24.9%)
  -> v3.3 DOMINATES v3.2b at equal FP (61.1% vs 24.9% recall)
```

`ML_DECISION_THRESHOLD` set to **0.6** in `rules.json` (0.35 SAFE < 0.6 ≤ 1.0 holds).
0.6 was chosen over 0.55 because it (a) drives the headline FP complaint down hardest
(6.39%), (b) most decisively clears the FP gate, and (c) on the curated stress set it
clears three hyphenated-legit false positives (`t-mobile`, `coca-cola`, `idfcfirstbank`,
all scoring 0.595) that 0.55 would keep. `test_config.py` updated to lock `== 0.6`.

**Net measured effect (v3.2b → v3.3, both at their shipped operating points):**
| Metric | v3.2b | v3.3 | Δ |
|---|---|---|---|
| 80k legit FP sweep, model-only (`fp_sweep.py`) | 7,767 / **9.70%** @0.5 | 5,122 / **6.39%** @0.6 | **−2,645 FPs (−34% rel)** ✅ limit #1 |
| Bare-domain recall, 5k unseen (`fresh_recall_probe.py`) | ~**24.9%** @0.5 | **54.9%** @0.6 | **2.2×** ✅ limit #2 |
| Recall at *equal* FP (`operating_point.py`, gate 9.70%) | 24.9% | **61.1%** | **2.5×** — dominates |
| Homograph/IDN probe (`homograph_probe.py`) | 14/14 | **14/14** | held |
| byjus deep-path at model level (`byjus_pathfix_probe.py`) | 5/5 SAFE (worst 0.453) | **5/5 SAFE** (worst 0.554 < 0.6) | held |
| Curated stress set (`model_stress_test.py`) | 72.5% @0.5 | **75.0%** @0.6 | +2.5 pts |
| Offline regression suite (`pytest`) | 59 passed | **59 passed** | held |

**The gate is passed decisively.** The standing mandate is *revert if the model-only
9.70% FP rate regresses*. v3.3 delivers **6.39%** — a 34% relative reduction — so it
ships, no revert. (At an *equal* 0.5 threshold the tiny 40-URL stress set reads 70.0%
vs 72.5% — one extra error, entirely in the deliberately-adversarial hyphenated-legit
bucket, and reversed at the shipped 0.6. That is not the gated metric and is
noise-level on 40 URLs; the 80k sweep and 5k holdout are the statistically meaningful
numbers and both improve substantially.)

**Live E2E (backend v2.7, `/health` → `{model: v3.3, decision_threshold: 0.6}`).**
`google.com` / `byjus.com` / `byjus.com//////login/verify/account` → **SAFE** (0.001);
`verify-account-security-update.com` → PHISHING (1.0); and the clean bare-domain
phishing that v3.2b let through is now surfaced — `accountsverify.com` **SUSPICIOUS**
(ml 0.7115), `mybankportal.in` **SUSPICIOUS** (0.6301), `portal-access.io` **SUSPICIOUS**
(0.8331), `update-center.app` **PHISHING** (0.9939).

**Honest caveats (do not overclaim).**
- The 54.9% holdout recall is measured on the **same Phishing.Database feed family** the
  training rows came from. Cross-source recall (a *different* feed, or truly novel
  campaigns) will be lower — this number proves the model learned to generalize to
  *unseen domains of the same kind*, not that it solved zero-day phishing.
- A genuinely clean, brand-new domain like `fakebrand123.com` — no lexical tell of any
  kind — has a **hard URL-lexical ceiling**: no URL-only model can reliably catch it.
  Closing that gap needs a non-lexical signal (page content, live reputation feed), which
  §B4 showed is not available offline today. v3.3 raises the floor (bare-domain recall
  more than doubled); it does not repeal the ceiling. The live OpenPhish blocklist
  (`refresh_feeds.py`, §P2) remains the catch for known-active clean domains.

**New reproducible tooling:** `harvest_fresh_data.py` (feed → novel+clean split),
`fresh_recall_probe.py` (holdout recall at the live threshold),
`operating_point.py` (fair equal-FP cross-version comparison).

---

## ✅ v3.4 — Parent-vs-path generalization fix (2026-09-25, model v3.4, backend v2.8 @ threshold 0.6)

**Reported symptom (re-raised by the user):** a legit *parent* domain scores SAFE, but
appending a deep, keyword-stacked *path* tips it toward phishing. byjus.com looked fixed
only because it is on the trusted_roots allowlist — the allowlist **masked** the model
weakness, it did not cure it.

**Confirmed at the model level (rules bypassed) on legit domains NOT on the allowlist**
via the new `parent_path_probe.py`: on v3.3, **5 of 9** real legit hosts (tutorialspoint,
unacademy, vedantu, shiksha, collegedunia) flipped from bare-SAFE to over-threshold when
given the pathological path `/login/verify/account/secure/update/confirm/billing` (worst
0.6212 > 0.60). Realistic paths (`/user/profile/settings/account`) stayed SAFE — only the
7-keyword stack flipped.

**Root cause:** `url_augment.add_path` built a deep keyword-stacked path only **15%** of
the time, so legit hosts rarely saw such a path in training, while the numeric features
that count path depth / keyword-stacking are ×15 weighted — the model extrapolated on the
legit side. Fix = strengthen the *symmetric* decorrelation: deep-path rate **0.15 → 0.35**,
max depth **6 → 7** (`url_augment.py`), applied to BOTH classes so path shape stays
independent of the label. Retrained (same 150k/class, 22 feats, grouped split, A5 cleaning);
v3.3 artifacts backed up to `model_backup_v33_20260925/` first.

**Net measured effect (v3.3 → v3.4, both at shipped threshold 0.6):**
| Metric | v3.3 | v3.4 | Δ |
|---|---|---|---|
| Parent-vs-path flips, non-allowlisted legit (`parent_path_probe.py`) | **5/9** (worst 0.621) | **0/9** (worst 0.588) | ✅ fixed |
| 80k legit FP sweep, model-only (`fp_sweep.py`) | 6.39% | **6.91%** | +0.52 pts (≪ 9.70% gate) |
| Bare-domain recall, 5k unseen (`fresh_recall_probe.py`) | 54.9% | **56.7%** | +1.8 pts |
| Homograph/IDN (`homograph_probe.py`) | 14/14 | **14/14** | held |
| byjus deep-path at model level (`byjus_pathfix_probe.py`) | SAFE | **SAFE** (worst 0.516 < 0.6) | held |
| Curated stress (`model_stress_test.py`, hardcoded 0.5) | 70.0% | **70.0%** | held |
| Offline regression suite (`pytest`) | 59 passed | **59 passed** | held |

**Frontier is essentially unchanged vs v3.3** (`operating_point.py`: at equal FP the recall
matches within noise — isotonic calibration quantizes, so 0.60 gives 6.91%/56.7% and 0.62
gives 5.06%/51.9%). The unambiguous, no-cost win is the parent/path fix. **Gate passed**
(6.91% ≪ 9.70%) → shipped at 0.60 (keeps best recall; still a 29% cut vs the 9.7% baseline
the user flagged). Threshold unchanged, so no rules/test churn.

**Live E2E (backend v2.8, `/health` → `{model: v3.4, decision_threshold: 0.6}`):**
`vedantu.com` → SAFE (0.385); `vedantu.com/user/profile/settings/account` → **SAFE** (0.482,
score 2.94); `byjus.com//////login/verify/account` → SAFE (0.001); clean phish
`accountsverify.com` → SUSPICIOUS (0.732) — still caught.

**Residual (now a RULES effect, not the model):** the pathological
`vedantu.com/login/verify/account/secure/update/confirm/billing` still serves **SUSPICIOUS**
(score 3.05) — but the model alone rates it 0.516 (→ 1.55, well SAFE); the extra +1.5 is the
**keyword heuristic** (`W_KEYWORD`, fires when `ml_prob ≥ KEYWORD_MIN_PROB=0.4` and any
keyword appears in the URL). So an ordinary legit page like `site.com/account/settings` on a
non-allowlisted host sits near the SUSPICIOUS line (score ~2.94) purely because of this rule.
Candidate next step: raise `KEYWORD_MIN_PROB` (~0.4 → ~0.55) so the keyword bump only
corroborates when the model already leans phishing — needs a full-pipeline (rules-on) recall
check first, since it can affect borderline detections. **Now measured and shipped in backend
v2.9 — `KEYWORD_MIN_PROB` raised 0.40 → 0.55; see the "v2.9 — Keyword-rule operating point"
section directly below.**

**New tooling:** `parent_path_probe.py` (permanent regression probe for this bug class;
uses non-allowlisted legit hosts so it measures the model, not the allowlist).

---

## ✅ v3.5 — Training-pipeline correctness retrain (2026-09-28, model v3.5, backend v3.2.0 @ threshold 0.6)

**Why.** This was not a data change or a decision-surface change — it fixed two
*correctness* defects in how the model is trained and measured, found in the Phase-4/5
code audit. Same data regime as v3.4 (the same `fresh_phishing.csv` / `final_dataset.csv`
/ `legit_urls.csv`, `MAX_PER_CLASS=150k`), so any movement is attributable to the fixes,
not to new data. v3.4 artifacts backed up to `model_backup_v34_pre_phase5_20260928/`
(model + trainer) before retraining; the shipped v3.5 is snapshotted at
`model_backup_v35_20260928/`.

**M10 — no preprocessing leakage (`train_ml_strong.py`).** The TF-IDF vectorizers and the
`StandardScaler` used to be `.fit_transform`-ed on the **full** augmented set, and only
*then* was the grouped train/cal/test split taken. The base model always trained on
`X_train` alone, so this never leaked labels — but the feature *transform* (char/word
vocabulary + IDF, and the scaler mean/std) had seen the calibration and test rows, so the
reported held-out score was mildly optimistic. Fixed: the grouped split is now taken on
**row indices first**; the two vectorizers and the scaler are `fit` on the **train slice
only**; calibration and test are `transform`-only. The test report is now leakage-free end
to end. (Vocabulary saturates at `max_features` well before the held-out ~40% would matter,
so the decision surface barely moves — it is just honestly measured now.)

**M11 — deterministic training (`train_ml_strong.py`).** `XGBClassifier` had no
`random_state`/`n_jobs`, so XGBoost's parallel histogram build made training
order-nondeterministic (a re-run produced slightly different trees). Fixed:
`random_state=SEED, n_jobs=1`. Training is now bit-reproducible run to run — which is what
makes the golden model-only scores in `tests/test_feature_weights.py` a meaningful lock.

**H3 — single source of truth for the feature weights (already in serving).** The
`[0.05, 0.05, 15]` block-weight triple that had been hand-copied into ~12 files is now the
single shared helper `config.stack_features`; both the trainer and `predict_ml_only.py`
call it, so train and serve can never drift. Locked by `tests/test_feature_weights.py`.

**Gated — every check passed (else revert; it did not):**
| Metric | v3.4 | v3.5 | verdict |
|---|---|---|---|
| Model-only FP, 80k sweep @0.60 (`fp_sweep.py`) | 6.91% | **6.23%** | ✅ **improved**, ≪ 9.70% ceiling |
| Equal-FP recall @ 9.70% gate (`operating_point.py`) | 61.2% | **61.3%** | ✅ dominates at equal FP |
| Fresh-holdout recall @0.60 | 56.7% | 55.6% | within noise; equal-FP shows no regression |
| Homograph/punycode (`homograph_probe.py`) | 14/14 | **14/14** | ✅ |
| byjus deep-paths, model-level (`byjus_pathfix_probe.py`) | PASS | **PASS** (worst 0.524) | ✅ |
| Offline regression suite (`pytest`) | 128 | **128** | ✅ (golden soft-scores re-baselined) |
| Honest grouped test accuracy | ~74% | **74%** | ✅ leakage-free, not inflated |

The FP rate *fell* (6.91% → 6.23%) — removing the preprocessing leak made the held-out
geometry slightly cleaner rather than costing accuracy. This is a strict correctness win:
the shipped verdicts are essentially unchanged, but the training is now reproducible and
the evaluation honest.

**Live E2E (backend v3.2.0, `/health` → `{version: 3.2.0, model: v3.5, decision_threshold:
0.6, keyword_min_prob: 0.55}`):** `byjus.com/login/verify/account` → SAFE (risk 0.0,
"Globally trusted domain"); `secure-login-paypal-verify.com/account/update` → PHISHING
(risk 10.0); `zerodha.com` → SAFE (risk 0.96).

**New tooling / locks:** `tests/test_feature_weights.py` (locks `FEATURE_WEIGHTS`, the
`stack_features` geometry, a golden 22-length feature vector, and golden model-only scores
that trip on any weight/feature/model drift and force a conscious re-baseline through the
FP gate). `operating_point.py` now gates a candidate against the **currently shipped** model
(v3.5, 61.3%), not a frozen historical number, so the bar rises with each ship.

---

## ✅ v2.9 — Keyword-rule operating point (2026-09-25, NO model change, backend v2.9 @ `KEYWORD_MIN_PROB` 0.55)

**Follow-up to the v3.4 residual above.** v3.4 left one rule as the last source of
legit-host over-flagging: the keyword heuristic (`W_KEYWORD=+1.5`, fires when the model prob
≥ `KEYWORD_MIN_PROB` AND the URL contains any phishing keyword). At the shipped 0.40 this
bump pushed ordinary pages on non-allowlisted legit hosts (`/login`, `/account`,
`/secure/checkout`) over the SUSPICIOUS line even though the model alone rated them SAFE.

**Measured the trade with evidence before touching it** — `keyword_rule_probe.py` reproduces
the full 4-gate serving ladder (reuses main.py's own gate helpers + predict_ml_only's
model/allowlist/override; the two live network bumps stubbed to no-bump — conservative for
phishing, realistic for legit; the real local blocklist bump applied). Swept
`KEYWORD_MIN_PROB` over a balanced 8,000-phishing / 8,000-legit sample:

| `KEYWORD_MIN_PROB` | phishing recall | legit FP | vs 0.40 |
|---|---|---|---|
| **0.40** (was) | 70.65% | 3.84% | — |
| **0.55** (shipped) | 70.49% | 3.26% | −13 phishing, +46 legit fixed |
| 0.60 | 70.20% | 2.57% | −36 phishing, +101 legit fixed |

**This is a genuine trade, not a clean win** — so it was NOT shipped silently; the operating
point (0.55) was chosen by the user from the measured curve. The FP reduction is concentrated
in clean Tranco legit sites (6.85% → 5.80% at 0.55; final-source legit 0.83% → 0.73%). The 46
legit "wins" are real sites' ordinary pages (`littlegreene.com/account`,
`starmakerstudios.com/secure/checkout`, `yearbookdiscoveries.com/login`, banks
`raiffeisenbank.rs`, `imbankgroup.com`). The 13 phishing "losses" are genuinely malicious
URLs this rule was the only thing catching — compromised WordPress
(`llbfarm.com/wp-admin/user/verify`), a credential-redirect (`…?us.battle.net/login`), and a
leetspeak Google homograph (`go0gIe.com/sysupdate`, which the typo check misses at
edit-distance 2). Every boundary case sits in the SUSPICIOUS (soft-caution) band, never
PHISHING — so no hard block is gained or lost either way; only the soft-caution flag moves.

**Why 0.55:** it sits strictly between the SAFE fast-path (0.35) and the decision line (0.60),
so the keyword bump only corroborates once the model already leans phishing. Because isotonic
calibration quantizes the probabilities (mass clusters at ~0.5036 / 0.5163 / 0.5462, nothing
lands in [0.40, 0.50)), the settings 0.40 / 0.45 / 0.50 are identical — 0.55 is the first step
that actually moves the boundary, and 0.60 would start dropping the compromised-host cases
above.

**No model retrain** — this is a `rules.json` + `main.py` change only, so the 9.70% model-only
FP gate is structurally untouched (model stays v3.4). Locked by
`test_config.py::test_keyword_min_prob_operating_point` (asserts `== 0.55` and the
`0.35 < 0.55 < 0.60` ordering). New permanent tool: `keyword_rule_probe.py`.

---

## ✅ Honest cross-source recall — 2026-09-25 (measurement only, no model/rules change)

**Resolves the standing "same-feed" caveat.** Every recall number quoted above
(54.9% → 56.7%) is measured on `fresh_holdout.csv`, carved from the **same
Phishing.Database ACTIVE harvest** the model trained on. That is a same-feed-family
number and was flagged (here and in §"What you can honestly claim") as *likely
optimistic*. `cross_source_recall_probe.py` tests the harder question directly: how
many phishing URLs does the **model** catch when they come from a feed it never
trained on? Scored **model-only** (raw calibrated XGBoost via the exact
`hstack([Xc*0.05, Xw*0.05, Xn*15])` train/serve invariant) with the **local blocklist
AND trusted-root allowlist deliberately bypassed** — because OpenPhish/PhishTank URLs
*are* the local blocklist, a full-pipeline test would trivially read ~100% and prove
nothing about lexical generalization. The same-feed holdout is re-scored in the same
run as an anchor and **reproduced 56.7% @0.60 exactly**, validating the batch scorer.

| Source (model-only, rules+blocklist bypassed) | N | @0.60 | @0.50 |
|---|---|---|---|
| **Anchor** — same-feed holdout (`fresh_holdout.csv`) | 5,000 | 56.7% | 62.7% |
| **OpenPhish** — live independent feed, ALL | 600 | **78.2%** | 79.5% |
| **OpenPhish — NOVEL** (root unseen in training) | 108 | **70.4%** | 72.2% |
| PhishTank — snapshot, ALL | 58,081 | 75.6% | 77.2% |
| PhishTank — NOVEL | 0 | n/a | n/a |

**The honest cross-source number is OpenPhish NOVEL @0.60 = 70.4%** (zero leakage:
unseen feed *and* registrable root never seen in training). Two findings that matter:

1. **Cross-source recall is HIGHER than same-feed, not lower — so 56.7% was a
   pessimistic floor, not an optimistic ceiling.** The reason is compositional, not
   luck: `fresh_holdout` is **bare-domain-heavy** (harvested bare domains — the hardest
   slice, no path signal at all), while live feeds are **55–70% pathed**. Real phishing
   paths (`/login/verify/account…`) carry exactly the lexical signal the model reads, so
   a realistic feed scores higher even on *novel* roots. There is **no cross-source
   cliff** — the model transfers to a feed it never saw.
2. **PhishTank is not independent at the root level** — **0 of 58,081 roots were novel**
   (100% overlap with training; Phishing.Database aggregates PhishTank upstream). Its
   75.6% is therefore a *"does the model still fire"* sanity check, **not** a
   generalization measurement. Reported for completeness, not as a cross-source result.

**Why it isn't higher (honest ceiling):** 16.7% (OpenPhish) / 21.4% (PhishTank) of URLs
sit on a **trusted-allowlist root** — compromised-host / shared-host phishing where the
registrable domain is a legitimately-owned site hosting a malicious page. The model
**cannot and should not** flag those from the URL string alone; catching them is exactly
the job of the local blocklist (D1) and `refresh_feeds.py`. That layer + the model is
the system; this probe isolates the model on purpose.

**Bottom line:** the fresh-data retrain's recall gain is **real and transferable**, not a
same-feed artifact — the model catches **~70% of never-before-seen phishing roots from a
feed it never trained on**, and the modest FP investment (6.39% → 6.91% model-only)
bought recall that holds up cross-source. **Read-only probe, shares the train/serve
invariant** → re-runnable after any future retrain for a like-for-like comparison. New
permanent tool: `cross_source_recall_probe.py`.

---

## ✅ Decisive blocklist + allowlist integrity — 2026-09-27 (NO model change; backend v2.9 → v3.0.2)

**Scope: serving logic only (`main.py` + `rules.json` + `config.py`).** `model.pkl` is
**untouched** (still v3.4), so the model-only FP gate (`fp_sweep.py`, must stay ≤ 9.70%)
is **definitionally unaffected** — no retrain, no artifact backup needed. This block
reworks how the rule ladder in `/predict_url` **routes** a verdict; it changes serving
behaviour, not model weights.

The serving gate ladder is now: **Gate 1** ML score → **Gate 2** structural-critical
override (raw-IP / `@`-authority) → PHISHING 10.0 → **Gate 2b** blocklist → PHISHING 9.0
→ **Gate 2c** allowlist → SAFE → **Gate 3** confident-safe fast path → **Gate 4** weighted
heuristics.

**backend v3.0 — the blocklist is now a DECISIVE gate, not a weak weighted signal.**
Before, a blocklist hit only added `W_PHISHTANK` (+4.0) inside Gate 4. That was doubly
broken: (a) for a benign-*looking* blocklisted URL the model scores ~0, so the Gate-3
confident-safe fast path returned **SAFE before Gate 4 ever ran**; and (b) when Gate 4
did run, the confidence dampener **halved** the bump. The compromised-/weaponized-host
case (a real-looking clone page the model can't smell) is exactly where the blocklist
must win — so an **exact** normalized-URL match against the local ~76k-entry OpenPhish/
PhishTank snapshot (refreshable via `refresh_feeds.py`) now forces **PHISHING (score 9.0)**
at Gate 2b, checked *before* the Gate-3 fast path.

**backend v3.0.1 — shared-hosting carve-out (blocklist vs allowlist).** The blocklist
normally **yields** to the trusted-root allowlist (`override_reason is None` ⇒ the model
actually scored the URL). The one carve-out is a **shared-hosting commons**, where an
exact blocklist match **overrides** the allowlist:
`SHARED_HOSTING_ROOTS = {github.io, blogspot.com, wordpress.com, readthedocs.io,
workers.dev, ghost.io, tumblr.com}`. These roots are on the allowlist **only as an FP
guard** (the model over-flags legit tenant pages there 0.6–0.99), but their trust belongs
to the **platform, not the tenant** (`foo.github.io` is not GitHub), so a reported
phishing URL under one *should* flip. A legit page there is never on the blocklist, so it
stays SAFE — only the specific reported URL flips. **Real brand roots (`google.com`,
`paypal.com`) are deliberately NOT in the set**, so a stale feed entry can *never* flip a
brand. (User decision, AskUserQuestion: "Override on shared hosts only".)

- **7-root audit:** started from an illustrative 6; **dropped `netlify.com`** (corporate
  site — user sites live on the non-allowlisted `netlify.app`), **added `ghost.io` +
  `tumblr.com`** (same user-subdomain-blog category). **Excluded** the larger
  CDN/cloud/file-share/shortener commons (`amazonaws.com`, `googleusercontent.com`,
  `cloudfront.net`, `dropbox.com`, `bit.ly`, …) — brand-associated and a far wider
  surface; revisit as a separate decision.
- **Invariant:** `config.py` asserts `SHARED_HOSTING_ROOTS ⊆ TRUSTED_ROOTS` (a shared-host
  URL only reaches Gate 2b as a "Globally trusted domain" SAFE, so a non-subset entry
  could never fire).
- **Measured impact:** **2,745** known-phishing blocklist URLs live on these roots
  (blogspot 818, github.io 497, ghost.io 265, workers.dev 163, wordpress.com 2;
  readthedocs.io 0, tumblr.com 0) — every one of them was previously swallowed to SAFE by
  the allowlist. Live E2E: 6/6 real blocklisted shared-host samples → PHISHING;
  `requests.readthedocs.io`, `engineering.fb.com`, `google.com/account`,
  `paypal.com/signin` → SAFE.

**backend v3.0.2 — allowlist verdict is honored as SAFE (Gate 2c), fixing a real FP.**
Verification of v3.0.1 surfaced a **pre-existing** false positive:
`https://microsoft.github.io/monaco-editor/` (a genuine Microsoft project page) returned
**SUSPICIOUS**. Cause: the allowlist scores it trusted (`prob 0.001`), but Gate 3's
confident-safe fast path is **skipped** whenever a brand/subdomain flag fires — and
`microsoft` reads as a brand label under `github.io`. Gate 4 then adds
`W_BRAND (3.0) + W_SUBDOMAIN (3.0) = 6.003`, the dampener halves it to **3.0015**, a hair
over `T_SUSPICIOUS (3.0)`. Every `<brand>.github.io` project page (google.github.io,
kubernetes.github.io, facebook.github.io) hit the same trap — a direct violation of the
allowlist's documented contract: *"a curated allowlist … the model must never wrongly
flag."* Fix: once Gate 2b has had its override chance, an allowlisted URL that **survives**
short-circuits to **SAFE** at Gate 2c, instead of falling into heuristics that assume an
untrusted root. This is safe precisely because Gate 2b (blocklisted shared-host phishing)
runs first.

- **Narrow, intended side effect:** for the *excluded* cloud/CDN commons, the occasional
  heuristic-driven SUSPICIOUS on an exact-brand-label subdomain (e.g.
  `paypal.amazonaws.com`) is now consistently SAFE. That SUSPICIOUS was an **inconsistent
  artifact** (only fired when brand *and* subdomain both hit and the dampener math landed
  just over 3.0), not a designed detection layer, and silencing it aligns with the
  "keep trusted roots trusted" intent. If such phishing must be caught, the principled
  path is to add that root to `SHARED_HOSTING_ROOTS` (Gate 2b), not to lean on the artifact.

**Regression lock (`backend/tests/test_blocklist_gate.py`, predict_ml / network / log_event
stubbed so only routing is under test):** blocklist beats confident-safe; allowlist beats
blocklist *except* shared-host; shared-host blocklist → PHISHING with a "shared-hosting"
reason; real-brand root never flipped by a (stale) blocklist entry; localhost never
flipped; allowlist survives blocklist → SAFE; and a `microsoft.github.io`-shaped URL is
SAFE **not** SUSPICIOUS — with a teeth-check that the *same* URL, treated as
non-allowlisted, *does* trip the real brand+subdomain heuristics (proving Gate 2c is what
saves it). **Full suite: 69 passed.**

**Bottom line:** three serving-logic fixes — a decisive blocklist, a principled
shared-hosting carve-out over the allowlist, and an allowlist-integrity SAFE gate — that
together make the blocklist actually catch weaponized-host phishing (2,745 URLs
un-swallowed) while making the allowlist actually keep its "never wrongly flag" promise
(legit `<brand>.github.io` pages fixed). **Rules-only; model untouched → the 9.70%
model-only FP gate is unaffected.** Live: backend **v3.0.2**, model **v3.4**.

---

## A. Data limitations (these are the root causes)

**A1 — Path artifact: "URL has a path ⇒ phishing"  [P0]**
`build_dataset.py` labels raw **Tranco bare domains** as `legitimate` and
**OpenPhish/PhishTank full URLs** (which carry paths) as `phishing`. The model
learns the shortcut *path present = phishing*.
_Evidence:_ `byjus.com` → 0.004 SAFE, but `byjus.com/home` → 0.999 PHISHING.
→ Fix: give legit URLs realistic, **diverse** paths (see A2); optionally add a
small set of pathless phishing too.

**A2 — Legit path diversity is only 10 fixed templates  [P0]**
`build_legit_dataset.py` adds paths from a hardcoded list (`/login`,
`/account`, `/dashboard`, `/secure/checkout`, …). The model memorizes those
exact strings as safe and flags everything else.
_Evidence:_ `byjus.com/login` → 0.034 SAFE (it's a template) but
`byjus.com/home` / `/products/item/123` → ~1.0 PHISHING (not templates).
→ Fix: generate paths from a large, varied vocabulary (or sample real paths);
randomize depth, segments, query strings.

**A3 — Circular vocabulary: features and phishing data share the same 25 words  [P0]**
`generate_adversarial.py` builds phishing hostnames from the *same* 13 brands +
12 keywords that `features.py` counts. The model learns "these 25 tokens =
phishing" and cannot generalize.
_Evidence:_ `amazon-refund-claim-now.online` → 0.044 SAFE ("refund/claim" aren't
in the keyword list); 7/8 clean-looking phishing missed entirely.
→ Fix: expand & decouple vocab; train on **real** phishing text, not synthetic
strings derived from the feature list.

**A4 — Clean bare malicious domains absent from phishing training  [P1]  ✅ partly done v3.3**
Phishing examples are almost all pathed URLs or keyword-salad hostnames, so
short innocuous-looking domains (`accountsverify.com`, `mybankportal.in`) look
like the legit bare-domain class → false negatives.
→ Fix: include real short/clean phishing domains; lean on non-lexical signals
(domain age, reputation) for bare domains.
_(2026-09-24 investigation — measured, do not re-litigate with current feeds:_
_of the phishing corpus only 15.8% is bare-host and 7.2% is "clean bare-domain";_
_inspecting that 7.2%, it is overwhelmingly **free-host subdomains** (`*.weebly.com`,_
_`*.web.app`, `*.ddns.net` — which A5 rule (b) correctly drops as shared-root noise)_
_or **random gibberish** (`updconfs.com`, `r9wrgz...`), plus malformed junk. The_
_keyword-composed clean FNs the stress test exposes (`securelogin.co`,_
_`accountsverify.com`) are NOT present as a learnable class and sit in the lexical_
_region that overlaps legit hyphenated names (C4). So re-mining the current_
_OpenPhish/PhishTank/Kaggle snapshots would add noise, not signal — A4 needs a_
_FRESH external clean-phishing source or the non-lexical model signal (B4), not a_
_re-balance of existing data.)_
_(2026-09-24 — **partly resolved v3.3**: a FRESH source was found — Phishing.Database_
_`ACTIVE` (391,986 live domains). `harvest_fresh_data.py` mines 159,797 novel+clean_
_bare roots and trains them as the bare-domain phishing class. Unseen-holdout bare-domain_
_recall rose 24.9% → 54.9% (see the v3.3 status block). The residual gap is the_
_lexical-ceiling core: a genuinely tell-free brand-new domain still needs a non-lexical_
_signal, which remains B4's rejected-offline territory — covered at runtime by the live_
_OpenPhish blocklist, not the model.)_

**A5 — "Tranco top-1M = legitimate" injects label noise  [P1]  ✅ done v3.2b**
Top-1M contains URL shorteners, free hosting, and compromised sites that serve
phishing. Blanket-labeling them legit teaches the model wrong examples.
→ Fix: filter Tranco against known-bad feeds; drop shorteners/free-host TLDs
from the legit set. _(v3.2b: two surgical rules — drop phishing rows on curated
trusted roots, and drop shortener/free-host roots from both classes. A more
aggressive "root also seen in legit" rule was tried and reverted for regressing
the FP rate — see the P2 status block.)_

**A6 — Up-weighting is silently cancelled by dedup  [P2]**
`build_legit_dataset.py` does `SEED_LEGIT_URLS * 10` and `fp_urls * 5`, then
`list(dict.fromkeys(all_urls))` collapses identical strings back to one — so the
intended 10×/5× emphasis never happens.
→ Fix: up-weight via sample weights at training time, not string duplication.

**A7 — Kaggle label mapping is fragile  [P2]**
`build_dataset.py` maps only `{"1","bad","phishing"}` → phishing. Float labels
(`1.0`) or other encodings silently become `legitimate` (mislabeled). A missing
`url` column throws.
→ Fix: robust, explicit label mapping with validation + assertions.

---

## B. Feature limitations (`features.py`)

**B1 — `@` matched anywhere in the URL  [P0]**
Feature 11/12 and the Tier-1 rule use `"@" in url`, not "@ in the authority".
A legit page with an email in the query/path is force-flagged phishing.
_Evidence:_ `mystore.in/contact?email=help@mystore.in` → PHISHING (10.0).
→ Fix: only treat `@` in the netloc/authority (before the first `/`) as the
credential-hiding trick.

**B2 — Only 13 brands / 12 keywords / 9 suspicious TLDs  [P1]  ✅ done v3.1**
Real attacks impersonate thousands of brands (banks, telcos, govt, logistics)
and use many new gTLDs (.zip, .mov, .shop, .click…). Anything outside these
tiny lists is invisible to the lexical features.
→ Fix: expand lists substantially; consider a brand-embedding / known-domain
similarity approach instead of a 13-item list.

**B3 — No punycode / IDN homograph handling  [P1]  ✅ done v3.1**
`xn--pypal-4ve.com`-style homograph attacks bypass the ASCII fuzzy match.
→ Fix: decode punycode, add mixed-script and confusable-character detection.

**B4 — Model sees no non-lexical signal  [P1] — INVESTIGATED & REJECTED ON EVIDENCE 2026-09-24**
Domain age, SSL, and PhishTank live only in `main.py`'s heuristic gate — they
are **not** model features. The model judges the raw string alone.
→ Proposed fix: fold domain age / cert age / DNS / ASN features into the model input.
→ **Empirically rejected.** `backend/b4_signal_probe.py` fetched LIVE WHOIS age,
DNS resolvability, and TLS cert age for a fresh 100+100 sample from
`final_dataset.csv`. The proposed signal does **not** separate the classes in any
usable way, and what separation exists is a snapshot artifact:

| live signal (n=100/class) | phishing | legit | verdict |
|---|---|---|---|
| WHOIS resolves at all | 52% | 96% | only real gap — but it's takedown, not phishing-ness |
| median age of *live* domains | **5277 d (14.5 yr)** | 4864 d (13.3 yr) | live phishing is **older**, not younger |
| *live* domains that are FRESH (<1 yr) | **8%** | 10% | fresh-phishing signal is absent / inverted |
| ≥3 yr old (of live) | 87% | 80% | both overwhelmingly old |
| median TLS cert age | 35 d | 33 d | non-signal (Let's Encrypt auto-renew) |

The phishing rows still alive are **compromised-legit / shared-host roots**, so by
age they are indistinguishable from legit. The only class separator — "domain
still resolves" — is a **takedown artifact** of the ~April-2025 feeds, *not* a
property of live phishing (a live phishing URL resolves by definition). Folding it
in would teach **"unreachable ⇒ phishing"**, which is useless at inference (live
phish resolves) and actively harmful (21% of *legit* domains also failed WHOIS in
the same run — WHOIS rate-limits and transient outages would become false
positives). Cert age carries no signal at all. This holds for **both** a model
feature *and* a runtime gate. **Decision: B4 stays deferred, now on evidence, not
caution.** It only becomes validatable with a **fresh live-phishing feed** (domains
still up) — which is the real root cause and the sanctioned next direction ("train
with best data"). v3.2b remains live; the 9.70% FP gate is unregressed (nothing
shipped).

**B5 — Weak, gameable numeric features  [P2]**
Length, dot/hyphen/digit counts, entropy are easily manipulated and add noise.
→ Fix: keep the discriminative ones; drop or regularize the rest.

---

## C. Training & evaluation limitations (`train_ml_strong.py`, `test_ml_only.py`)

**C1 — Random split, not grouped by domain → leakage & optimistic 98%  [P0]  ✅ done v3.0, completed v3.5**
`train_test_split` splits by row, so the same domain (many pathed rows) can land
in both train and test. The model memorizes domains; the held-out score is
inflated.
→ Fixed: **grouped split by registrable domain** (`GroupShuffleSplit`, v3.0) so no
domain is shared across splits. **v3.5 (M10)** closed the last leak on this axis —
the vectorizers/scaler are now fit on the train slice only, not the full set before
the split — so the held-out score is honest end to end (~74% grouped, model-only).
(A temporal split remains a possible future refinement.)

**C2 — Probability calibration fit and evaluated on the same test set  [P1]  ✅ done v3.0**
`CalibratedClassifierCV(...).fit(X_test, y_test)` then the classification report
is computed on that same `X_test`. Calibration quality and the reported metrics
are both optimistic.
→ Fixed: **three-way split — train / calibrate / test on disjoint groups** (v3.0);
isotonic calibration is fit on its own held-out slice, disjoint by domain from both
train and test.

**C3 — Text features are near-dead weight  [P1]**
`hstack([X_char*0.05, X_word*0.05, X_num*15])` makes the 4,000 TF-IDF features
almost irrelevant vs the 20 numeric features. The "char+word n-gram" model is
mostly decorative.
→ Fix: let the model learn feature importance (drop the hand-set ×0.05/×15
scales; standardize and let XGBoost weight them), or justify the weighting
empirically.

**C4 — Balanced 50/50 training vs rare real-world base rate  [P1]**
Most real traffic is legitimate; training at 50% phishing biases the model
toward over-flagging (feeds the path-artifact over-sensitivity).
→ Fix: train nearer the real base rate or use class weights; tune the decision
threshold on a realistic validation set (0.50 is arbitrary).

**C5 — The "100%" test suite mostly tests the rules, not the model  [P1]**
Most of the 31 cases in `test_ml_only.py` are decided by the allowlist
(bbc.com, coursera.org…) or by structural overrides (`@`, IP, brand-spoof) —
only ~3 truly exercise the Tier-2 model. "100%" is not a model score.
→ Fix: a separate **model-only** eval set (rules bypassed) with a confusion
matrix — like `model_stress_test.py`, which shows ~65% on a realistic mix.

**C6 — Single split, fixed seed, no cross-validation  [P2]  ◑ partially addressed v3.5**
No variance estimate; one lucky/unlucky split.
→ **v3.5 (M11)** pinned `random_state=SEED, n_jobs=1` so training is now
bit-reproducible (the split, the XGBoost fit and every audit number are stable run
to run), and the FP/recall frontier is measured on an 80k legit sweep + a 5k unseen
holdout + two independent cross-source feeds — so the operating point is not resting
on one lucky test slice. A full **grouped k-fold CV with mean ± std** is still the
remaining refinement for a formal variance estimate.

---

## D. Runtime pipeline limitations (`main.py`)

**D1 — PhishTank signal is effectively dead  [P1]  ✅ done v3.2b**
`check_phishtank` POSTs to the old public endpoint (now key-gated / deprecated)
over `http://`; it will almost always return False, so `W_PHISHTANK` rarely
contributes.
→ Fix: use an authenticated feed or a local bloclist snapshot; or remove and
re-weight. _(v3.2b: replaced with `_load_local_blocklist()` — an exact
normalized-URL membership test against a local OpenPhish/PhishTank snapshot loaded
at startup, `RAW_FEED_DIR` env-configurable; the dead live POST and `requests`
import removed.)_

**D2 — SSL used as a legitimacy signal  [P1]  ✅ done v3.1**
Gate 3 only calls a site SAFE if `ssl_valid`; Gate 4 penalizes "no SSL". Modern
phishing overwhelmingly has valid (Let's Encrypt) certs, and legit sites can
fail the check on flaky networks → both false positives and false negatives, and
**non-deterministic verdicts** across runs.
→ Fix: treat SSL presence as near-noise; use **certificate age/issuer**, not
mere validity.

**D3 — Live WHOIS per request  [P1]**
`get_domain_age` is slow, rate-limited, and often returns -1 → the "new domain"
signal is frequently unavailable.
→ Fix: cache/batch WHOIS or use a passive-DNS/age provider; degrade gracefully.

**D4 — Brand-spoof override can hit 10.0 on a false match  [P2]  ✅ done v3.1**
Any `feats[8]` fuzzy match >85 against the 13 brands forces PHISHING 10.0 with
no appeal, so a legit name resembling a brand is unrecoverably flagged.
→ Fix: require corroboration (brand token + different registrable domain) before
the absolute override.

**D5 — No input hardening  [P2]  ✅ done v3.1**
No max-length, no rate limiting, `CORS=*`, no defanged-URL normalization
(`hxxp://`, `[.]`).
→ Fix: validate/normalize input; lock CORS for anything beyond local demo.

---

## E. Architectural limits (inherent to a URL-string-only model)

- A lexical URL classifier can never see page content, redirect chains, form
  targets, or JS — the strongest phishing signals. It will always miss
  clean-domain zero-day phishing and over-rely on surface patterns.
- No drift monitoring or automated retrain loop (`pending_retrain.csv` is
  collected but only manually consumed).
- The allowlist is currently **masking** the model's weaknesses for the top 243
  domains — good as a safety net, but it hides how often the model would err.

---

## Prioritized improvement roadmap

### P0 — do first (restores real-world accuracy)
1. **Fix the data → retrain** (A1, A2, A3): diverse randomized legit paths +
   decoupled/expanded phishing vocab + real pathless phishing. This is the
   single biggest win — it removes the path artifact and the vocabulary
   shortcut. _(= "retrain to kill the path artifact", expanded.)_
2. **Scope the `@` rule to the authority** (B1) — quick, no retrain.
   _(= original fix #2.)_
3. **Grouped/temporal split + honest model-only eval** (C1, C5) — so the
   accuracy number means something.

### P1 — high value
4. Lean on non-lexical signals for bare domains (A4, B4, D2, D3) — fold domain
   age / cert age into the model; stop trusting mere SSL validity.
   _(= original fix #3, deepened.)_
5. Expand brands/keywords/TLDs + punycode handling (B2, B3).
6. Three-way split for calibration; tune the threshold; near-real base rate
   (C2, C4).
7. Replace/repair the PhishTank feed (D1).

### P2 — hardening
8. Up-weight via sample weights not duplication (A6); robust Kaggle mapping
   (A7); learn feature scales (C3); grouped CV (C6, ◑ partially — v3.5 pinned
   determinism, full mean±std CV still open); corroborate brand override
   (D4 ✅ v3.1); input hardening (D5 ✅ v3.1).
9. **✅ done v3.1.0 (2026-09-28)** — full security/robustness code audit of
   backend + frontend + extension (parsed-host checks, off-loop inference,
   CSV-injection neutralization, DOM-XSS fix, MV3 banner rebuild, request
   timeouts, runtime-configurable API base, a11y). See the hardening claim below.
10. **✅ done v3.5 (2026-09-28)** — training-pipeline correctness: no
    preprocessing leakage (M10, completes C1), deterministic training (M11,
    partially addresses C6), single-source feature weights (H3, addresses C3's
    drift risk). Re-gated; model-only FP 6.91% → 6.23%.

---

## What you can honestly claim

_(Updated 2026-09-28: v3.1.0 security/robustness hardening + v3.5 training-pipeline
correctness retrain. Earlier entries date from the v3.0 → v3.4 / backend v3.0.2 line
above; the newest claims are at the end of this list.)_

- ✅ "I trained a calibrated XGBoost URL classifier and **fixed the dataset
  artifacts that were faking its accuracy**: it no longer keys on 'URL has a
  path', its phishing vocabulary is decoupled from the feature list, and it's
  evaluated with a leakage-free split grouped by domain."
- ✅ "On a held-out set of ~13,700 domains it never saw in training, the model
  alone scores **77%** (legit recall 0.91, phishing precision 0.83) — an honest
  generalization number, not the old leakage-inflated ~98%."
- ✅ "It's wrapped in a curated allowlist + structural rules as a safety layer
  (defense-in-depth), and the `@` credential-trick rule is scoped to the
  authority so a legit URL containing an email is no longer force-flagged."
- ✅ _(v3.1)_ "It now decodes punycode/IDN hosts and de-confuses look-alike
  characters, so a homograph brand-spoof like `xn--pypal-4ve.com` is caught —
  validated 14/14 on a dedicated homograph/typosquat probe — while real brand
  roots stay SAFE. Brand, keyword and TLD coverage was expanded (32/41/19), the
  brand-spoof override now requires corroboration before it can force a verdict,
  the SAFE fast-path is deterministic (no longer gated on flaky SSL), and input
  is de-fanged/length-capped."
- ✅ _(v3.2b)_ "I cleaned host-level label noise (curated trusted roots never
  train as phishing; shortener/free-host roots dropped from both classes) and
  measured it on a reproducible **80,110-URL model-only legit sweep**: the raw
  model's false-positive rate fell **10.37% → 9.70%** while homograph detection
  held 14/14 and the path artifact stayed dead. The reported `byjus.com`
  deep-path false positive is fixed at three layers — deep-path decorrelation in
  training, redundant-slash collapse in normalization, and a `trusted_roots`
  allowlist safety net — so every `byjus.com` path variant now scores SAFE. The
  dead PhishTank POST was replaced with a local blocklist snapshot."
- ✅ _(v3.3)_ "I found a fresh live-phishing source (Phishing.Database ACTIVE,
  391,986 domains), mined **159,797 novel, clean bare domains** from it, and
  retrained on them. Measured on an **unseen 5,000-domain holdout**, bare-domain
  phishing recall rose **24.9% → 54.9%** (2.2×), and — because the retrain shifted
  the FP/recall frontier — I could raise the decision threshold to 0.60 and cut the
  model-only legit false-positive rate **9.70% → 6.39%** at the *same time*. At an
  equal false-positive rate the new model catches **2.5× more** unseen phishing
  (61.1% vs 24.9%), so it strictly dominates the previous one (`operating_point.py`).
  Homograph stays 14/14, the byjus fix holds, and 59 offline regression tests pass."
- ⚠️ Still true / next: a URL-string-only model cannot see page content or
  reputation, so it still misses some clean bare-domain phishing and
  over-flags some hyphen-heavy legit names. These are the documented remaining
  items (non-lexical **model** signals, real clean-phishing data, a live
  reputation feed) — not artifacts, the genuine hard core.
- ✅ _(cross-source, 2026-09-25)_ "I verified the recall gain is **not a same-feed
  artifact**. Scoring the model (rules + blocklist bypassed) on **OpenPhish**, a live
  feed it never trained on, it catches **70.4% of never-before-seen phishing roots**
  (unseen feed *and* unseen registrable domain) and 78.2% of all OpenPhish URLs — and
  the same-feed holdout re-scored in the same run reproduced 56.7% exactly, validating
  the scorer. Cross-source recall is *higher* than same-feed because the same-feed
  holdout is bare-domain-heavy — the hardest slice — so 56.7% is a floor, not a ceiling
  (`cross_source_recall_probe.py`)."
- ⚠️ _(v3.3 honesty, corrected 2026-09-25)_ My earlier hedge here — "recall on a
  genuinely different source will be *lower*" — was **wrong in direction**: the
  cross-source probe above measured it *higher* (70.4% novel vs 56.7% same-feed),
  because `fresh_holdout` is bare-domain-heavy while live feeds carry pathed URLs the
  model reads well. What remains true is the hard core: a completely tell-free brand-new
  domain (`fakebrand123.com`) is a URL-lexical ceiling no URL-only model repeals, and
  compromised-host phishing on a legit root (16–21% of live feeds) is a lexical blind
  spot by construction — both are covered at runtime by the live OpenPhish blocklist and
  `refresh_feeds.py`, not the model.
- ✅ _(blocklist + allowlist integrity, 2026-09-27, serving logic only — no retrain)_
  "I made the known-phishing blocklist a **decisive verdict** instead of a weak weighted
  signal: an exact OpenPhish/PhishTank match now forces PHISHING *before* the confident-safe
  fast path, so weaponized pages on real-looking hosts stop slipping through. It overrides
  the trusted-root allowlist **only** for shared-hosting commons (`github.io`,
  `blogspot.com`, … — where trust belongs to the platform, not the tenant) and **never**
  for a real brand root, which un-swallowed **2,745** blocklisted URLs the allowlist had
  been forcing to SAFE. I then fixed the mirror-image bug: an allowlisted trusted root
  (e.g. `microsoft.github.io`) could be dragged to SUSPICIOUS by the brand/subdomain
  heuristics, so an allowlist hit that survives the blocklist now short-circuits to SAFE —
  restoring its 'never wrongly flag' contract. **All rules-only: the model is untouched, so
  the 9.70% model-only FP gate is unaffected**, and **69** offline regression tests lock the
  gate ordering."
- ✅ _(security & robustness hardening, 2026-09-28, backend v3.1.0 — no model change)_
  "I ran a full code audit of the backend, frontend and Chrome extension and fixed the
  findings: the host-based security checks (loopback, trusted-root, raw-IP, `@`-authority)
  now key on the **parsed host**, not substrings of the URL, closing a `localhost`-in-path
  SAFE bypass and a dotted-quad-in-path false IP flag; model inference and event logging run
  off the event loop and can no longer 500 a verdict; CSV formula injection in exports is
  neutralized. In the client I fixed a DOM-XSS (attacker-controlled URL rendered via
  `innerHTML` → `textContent`), rebuilt the extension's broken MV3 warning banner without
  CSP-violating `eval`/`new Function`, dropped a redundant permission, added request
  timeouts and a bounded cache, made the API base URL runtime-configurable (no hardcoding),
  and added accessibility labels/roles."
- ✅ _(v3.5 training-pipeline correctness, 2026-09-28)_ "I fixed two correctness defects in
  how the model is trained and measured, then retrained on the same data and re-gated. The
  TF-IDF vectorizers and scaler are now fit on the **train slice only** (previously the full
  set was fit before the grouped split, making the held-out score mildly leaky), and training
  is **bit-reproducible** (`random_state` + `n_jobs=1`). The block-weight triple is now a
  single shared helper so train and serve can't drift. Re-gated: the model-only false-positive
  rate **fell 6.91% → 6.23%** on the 80k sweep, equal-FP recall held (61.2% → 61.3%), homograph
  stayed 14/14, and the byjus deep-path fix held — a strict correctness win with the verdicts
  essentially unchanged. Golden feature-vector and model-score locks (`test_feature_weights.py`)
  now trip on any future weight/feature/model drift; **128** offline regression tests pass."
- ❌ Do **not** claim "98% real-world accuracy." That figure came from an
  in-distribution split with domain leakage and is retired.
