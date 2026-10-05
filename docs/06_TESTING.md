# 06 — Testing & Model-Quality Measurement

Testing in this project is split into **two complementary layers**, and knowing the difference is a
strong interview point:

1. **The offline pytest suite** (128 cases) — locks the **behavioral contracts** (does the code
   still do what it must?). Deterministic, no network, no retrain, runs in seconds.
2. **The statistical probes** — own the **quality numbers** (how *good* is the model?). They score
   the model over thousands of URLs (FP rate, recall, etc.).

> **Why two layers?** A green unit test doesn't prove the model is *accurate*, and a good accuracy
> number doesn't prove a future edit didn't silently break the `@`-rule or the feature vector. You
> need both: contracts that can't regress, and metrics that measure quality.

---

## 1. What "regression testing" means here

A **regression** is when a change **re-breaks** something that used to work. This project has a
history of exactly that risk: fixing the byjus path bug, the 14/14 homograph set, the 22-length
feature vector, the `@`-authority scoping, the blocklist loader — any future edit or retrain could
silently undo one of these while all the printed output still *looks* fine.

Before the suite existed, the only "tests" were **print-only scripts with no assertions** — nothing
mechanically caught a regression. The pytest suite is the fix: **assertions that fail loudly** if a
contract breaks, runnable in one command as a gate on every change.

Because the suite **touches no model artifact and makes no network call**, it **cannot** regress the
9.70% FP gate — it locks behavior *around* the model, while the probes own the model's numbers.

---

## 2. The offline pytest suite (128 cases)

Run:
```bash
cd backend && python -m pytest
```
`conftest.py` `chdir`s into `backend/` (so the model artifacts and `../data/raw` load correctly) and
puts it on `sys.path`. **62 test functions** across **10 files** expand — via `@pytest.mark.parametrize`
(one function running many input cases) — to **128 executed cases**, all passing.

| File | Test fns | What it locks |
|---|---|---|
| **test_features.py** | 7 | `extract_features()` is **always length 22**; the exact meaning of the security indices — IP (10), `@`-in-**authority-only** (11, and an email in the *query* does **not** fire), punycode (20), non-ASCII host (21), suspicious TLD (16), brand-spoof (8, incl. the `g00gle` look-alike; and `google.com` root is **not** a spoof) |
| **test_feature_weights.py** | 5 | The **`FEATURE_WEIGHTS = (0.05, 0.05, 15)`** triple, the `stack_features` geometry, a **golden 22-length feature vector**, and **golden model-only scores** — any weight/feature/model drift trips these and forces a conscious re-baseline through the FP gate |
| **test_config.py** | 6 | `trusted_roots` is a lowercase set (>100) containing `google.com`/`byjus.com`; `ML_SAFE < ML_DECISION`; `ML_DECISION_THRESHOLD == 0.6`; `KEYWORD_MIN_PROB == 0.55` with the `0.35 < 0.55 < 0.60` ordering; `T_SUSPICIOUS < T_PHISHING`; `strip_www` is a true-prefix strip (`www.whatsapp.com` → `whatsapp.com`, not `hatsapp.com`) |
| **test_host_parsing.py** | 10 | The **parsed-host** security helpers — `parse_host`, `host_is_ip`, `host_is_loopback` — key on the real host, not URL substrings (closes the `localhost`-in-path bypass and the dotted-quad-in-path false IP flag) |
| **test_main_helpers.py** | 7 | `_normalize_url` de-fangs (`hxxp`, `[.]`, `[dot]`) and collapses redundant slashes (`byjus.com//////login` → `.../login`) while preserving `://`, plus the 2048 cap; `extract_domain` `@`/port/www stripping; `levenshtein`; `check_typo`/`check_subdomain` |
| **test_url_augment.py** | 4 | `registrable_domain` incl. two-part TLDs (`a.b.co.uk` → `b.co.uk`) and `@`/port stripping; `has_path`; `add_path` determinism under a seeded RNG |
| **test_model_invariants.py** | 5 | End-to-end `predict_ml`: trusted roots + localhost **never** flagged; raw-IP and `@`-credential **force** PHISHING; the **full 14-case** homograph+typosquat+control set stays **14/14**; byjus deep-path stays **below the 0.5 threshold at the model level**. It imports the cases and serving weights **directly from `homograph_probe.py`**, so the suite and the probe can never silently diverge |
| **test_blocklist.py** | 2 | The blocklist loader populates a `frozenset` (>1000 entries) and matches a known entry (and its trailing-slash form) but not an arbitrary URL |
| **test_blocklist_gate.py** | 9 | The **gate ordering** (routing): blocklist beats confident-safe; allowlist beats blocklist **except** shared-host; shared-host blocklist → PHISHING; a real-brand root is **never** flipped by a stale blocklist entry; localhost never flipped; allowlist survives blocklist → SAFE; a `microsoft.github.io`-shaped URL is **SAFE not SUSPICIOUS** — with a teeth-check that the *same* URL treated as non-allowlisted *does* trip the brand+subdomain heuristics (proving Gate 2c is what saves it). `predict_ml`/network/`log_event` are stubbed so **only routing** is under test |
| **test_robustness.py** | 7 | Malformed/edge-case inputs don't crash: empty URLs, huge URLs, weird encodings, exception-path returns `[0]*22`, etc. |
| **conftest.py** | 0 | Shared fixtures + the `chdir`/`sys.path` setup |

**What makes these good tests:** they assert **contracts, not implementation** — "the feature vector
is length 22", "an email in the query must not fire the `@` rule", "a stale blocklist entry must
never flip `google.com`". Each one maps to a **specific past bug or a must-not-break guarantee**.

---

## 3. The statistical probes (the quality numbers)

These are **not** unit tests — they score the model over large URL sets to produce the metrics.
They share the **exact serving feature weights** (`hstack([Xc*0.05, Xw*0.05, Xn*15])`), so their
numbers are like-for-like with production.

| Probe | Measures | Headline result (v3.5) |
|---|---|---|
| **`fp_sweep.py`** | Model-only **false-positive rate** on **80,110** legit URLs — the gated metric | **6.23%** (hard ceiling ≤ 9.70%) |
| **`operating_point.py`** | **Recall at equal FP** — the *fair* cross-version comparison (compares two models at the same FP, not the same threshold) | **61.3%** at the 9.70% gate; dominates every prior version |
| **`cross_source_recall_probe.py`** | Recall on a feed the model **never trained on**, rules+blocklist bypassed — the honest generalization test | **70.4%** on OpenPhish **novel** roots |
| **`fresh_recall_probe.py`** | Recall on the 5k unseen same-feed holdout | **55.6%** @ 0.60 |
| **`homograph_probe.py`** | Punycode/IDN + typosquat detection (the canonical 14-case set) | **14/14** |
| **`parent_path_probe.py`** | The parent-vs-path bug class, on **non-allowlisted** legit hosts (so it measures the *model*, not the allowlist) | **0/9** flips (was 5/9) |
| **`byjus_pathfix_probe.py`** | The byjus deep-path artifact at the model level | all SAFE (worst 0.524 < 0.6) |
| **`model_stress_test.py`** | A curated realistic mix, model-only | ~74–75% |
| **`keyword_rule_probe.py`** | The keyword-rule operating point (full 4-gate ladder, network stubbed) | chose `KEYWORD_MIN_PROB = 0.55` from the measured curve |

### Why "recall at equal FP" matters (a subtle, impressive point)

Comparing two models at the **same threshold** is misleading — a retrain shifts the whole
probability distribution, so "more phishing caught" might just mean "more of everything flagged
(including legit)". The fair question is: **at the same false-positive budget, which model catches
more phishing?** `operating_point.py` answers exactly that, and it's how v3.3 was shown to
**dominate** v3.2b (61.1% vs 24.9% recall at equal FP), not just trade FP for recall.

### Why the cross-source probe bypasses the blocklist

OpenPhish/PhishTank URLs **are** the local blocklist — a full-pipeline test would trivially read
~100% and prove nothing about the *model's lexical generalization*. So the probe scores the **model
only**, with blocklist and allowlist deliberately bypassed, to isolate what the model itself learned.
It re-scores the same-feed holdout in the same run as an anchor (reproduced 56.7% exactly),
validating the scorer.

---

## 4. The testing philosophy (say this in an interview)

> *"I separate behavioral tests from quality metrics. The 128 pytest cases are fast, offline, and
> deterministic — each one locks a contract tied to a real bug: the feature vector stays length 22,
> an email in a query never triggers the `@`-credential rule, a stale blocklist entry can never flip
> a real brand to phishing. They can't measure accuracy, and they're not meant to — they guarantee I
> don't re-break a fixed bug. The model's actual quality is owned by statistical probes over tens of
> thousands of URLs: an 80k false-positive sweep, an equal-FP recall comparison, and a cross-source
> recall test on a feed the model never trained on. Every retrain is gated: if the false-positive
> rate regresses past 9.70%, it's reverted."*

---

## 5. The gate that governs every retrain

The standing rule: **the model-only false-positive rate must stay ≤ 9.70%** on `fp_sweep.py`. Every
retrain (v3.0→v3.5) backs up the previous artifacts first, retrains, re-runs the probes, and is
**shipped only if it clears the gate** — otherwise reverted. v3.5 sits at **6.23%**, clearing it
decisively. This is what makes "I retrained it five times and it kept getting better" a *verifiable*
claim rather than a vibe.

Next: [07_INTERVIEW_QA.md](07_INTERVIEW_QA.md) — the anticipated interview questions with answers.
