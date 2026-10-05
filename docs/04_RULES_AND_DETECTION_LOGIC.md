# 04 — Rules & Detection Logic (the 6-gate serving ladder)

The model (doc 03) produces a probability. This document explains the **thin rule layer around it**
that produces the final verdict — every gate, every weight, every threshold, and *why each exists*.

---

## 1. Why rules at all, if there's a model?

A URL-string-only model has **provable blind spots** that no amount of training fixes:
- It **cannot** know that a specific URL was *reported* as live phishing yesterday (that's external
  knowledge → **blocklist**).
- It **shouldn't** ever flag `google.com` or `sbi.co.in`, even on a weird path, because the cost of
  a false positive on a top bank is unacceptable (→ **allowlist**).
- Some attacks are **structural certainties**, not probabilities: a raw IP host or a
  credential-hiding `@` is malicious by construction (→ **structural overrides**).

So the design is **defense-in-depth**: the model is the general-purpose brain, and the rules handle
the cases where external knowledge or hard guarantees beat a probability. Crucially, **the model
runs first** and the rules are a principled wrapper — not a pile of rules with ML bolted on.

> **Interview answer to "which is checked first, rules or model?"** *"The **model runs first** — it
> scores every URL at Gate 1. The rules then interpret that score: structural certainties and a
> known-bad blocklist can override it upward, a trusted-domain allowlist can clear it, and for
> everything in between a weighted heuristic combines the model probability with a few structural
> signals. It's a model-first system with a rule safety-net, not a rule engine."*

---

## 2. The two thresholds that shape everything

From `rules.json` → `config.py`:
- **`ML_SAFE_THRESHOLD = 0.35`** — below this the model is *confidently* safe.
- **`ML_DECISION_THRESHOLD = 0.60`** — at/above this the model calls it phishing (`pred=1`).
- Between 0.35 and 0.60 is the **uncertain band**, where the weighted heuristics decide.

And the two **score** thresholds (0–10 scale) for the final verdict:
- **`T_PHISHING = 4.5`** — score ≥ 4.5 → **PHISHING**.
- **`T_SUSPICIOUS = 3.0`** — score ≥ 3.0 (and < 4.5) → **SUSPICIOUS**; below → **SAFE**.

---

## 3. The 6-gate ladder (exact order, with code-level logic)

This lives in `main.py`'s `predict_url_endpoint`, after `_normalize_url()`. Order is
load-bearing — each gate assumes the ones above it already ran.

### GATE 1 — The ML model scores the URL (always runs first)

```python
pred, prob, override_reason = await asyncio.to_thread(predict_ml, url)
```
`predict_ml` (in `predict_ml_only.py`) returns the probability **and** an `override_reason` that
encodes *why* it reached its conclusion. That reason drives the branching below. (Running it via
`asyncio.to_thread` keeps CPU-bound inference off the event loop.)

Inside `predict_ml`, three short-circuits can set `override_reason` before the soft model even
matters:
- **loopback host** → `(0, 0.001, "Localhost dev environment")`
- **registrable root ∈ TRUSTED_ROOTS** → `(0, 0.001, "Globally trusted domain")`
- **structural-critical** → `(1, 0.999, "Critical: Structural security risk detected")`, where
  structural-critical =
  `host_is_ip(host)` **OR** `feats[11]` (`@` in authority) **OR** `brand_spoof_corroborated`, and
  `brand_spoof_corroborated = feats[8] AND (feats[9] OR feats[16] OR feats[20] OR feats[21])`.

### GATE 2 — Structural-critical override → PHISHING 10.0

```python
if override_reason and "Critical" in override_reason:
    return PHISHING, risk_score = 10.0
```
A raw-IP host, an `@`-credential trick, or a **corroborated** brand spoof is malicious by
construction — maximum score, no appeal. (Corroboration matters: a brand look-alike **alone** no
longer forces this — it needs a keyword, suspicious TLD, or IDN/homograph signal too, so a legit
name that merely resembles a brand isn't nuked.)

### GATE 2b — Decisive blocklist → PHISHING 9.0

```python
if check_blocklist(url) and (override_reason is None or _shared_host_allowlisted):
    return PHISHING, risk_score = 9.0
```
An **exact normalized-URL match** against the local OpenPhish/PhishTank snapshot (~76k entries,
loaded once into a `frozenset`) forces PHISHING — **before** the confident-safe fast path, so a
benign-*looking* but reported-malicious page can't slip through as SAFE.

- The blocklist normally **yields to the allowlist** (`override_reason is None` means the model
  actually scored it — no trusted-root short-circuit fired).
- **The one carve-out:** for **shared-hosting commons** (`github.io`, `blogspot.com`,
  `wordpress.com`, `readthedocs.io`, `workers.dev`, `ghost.io`, `tumblr.com`) a blocklist hit
  **overrides** the allowlist — because trust there belongs to the *platform*, not the *tenant*
  (`evil.github.io` is not GitHub). Real brand roots are deliberately **not** in this set, so a
  stale feed entry can never flip `google.com`.

### GATE 2c — Trusted-root allowlist → SAFE (allowlist integrity)

```python
if override_reason == "Globally trusted domain":
    return SAFE, score = prob * 3   # prob is ~0.001, so ~0
```
If a URL's registrable root is on the ~245-entry allowlist and it **survived** the blocklist gate,
it short-circuits to **SAFE** — instead of falling into heuristics that assume an untrusted root.
This fixed a real bug where `microsoft.github.io` (a genuine Microsoft page) was dragged to
SUSPICIOUS by the brand+subdomain heuristics. Safe precisely because Gate 2b (blocklisted
shared-host phishing) already ran.

### GATE 3 — Confident-safe fast path → SAFE

```python
if pred == 0 and prob < 0.35 and not (typo_flag or subdomain_flag or brand_flag):
    return SAFE
```
If the model is confidently safe (`prob < 0.35`) **and** none of the cheap structural red flags
fire (typosquat / brand-in-subdomain / brand-in-domain), clear it fast. The extra flag check stops
a low model score from waving through an obvious typosquat.

### GATE 4 — Weighted heuristics + confidence dampener

The uncertain middle. Start from the model and add structural evidence:
```python
score = prob * 3.0                     # model contributes up to ~3 points
score += W_BRAND      (3.0)  if brand look-alike
score += W_TYPO       (3.0)  if typosquat
score += W_SUBDOMAIN  (3.0)  if brand-in-subdomain
score += W_IP         (2.5)  if raw IP
score += W_KEYWORD    (1.5)  if a phishing keyword AND prob >= KEYWORD_MIN_PROB (0.55)
score += W_NEW_DOMAIN (1.0)  if domain age < 30 days (optional WHOIS signal)
score += W_NO_SSL     (0.5)  if SSL invalid (mild)
# confidence dampener:
if prob < DAMPENER_THRESHOLD (0.3):
    score *= 0.5                        # halve when the model is confident it's safe
```
Then the final verdict:
```python
if score >= T_PHISHING (4.5):     PHISHING
elif score >= T_SUSPICIOUS (3.0): SUSPICIOUS
else:                             SAFE
```

**Two design details that matter:**
- **The keyword bump is gated on the model** (`prob ≥ 0.55`). Otherwise every legit `/login` or
  `/account` page would get +1.5 and drift into SUSPICIOUS. Raising this from 0.40 to 0.55 (backend
  v2.9) was a *measured* trade: −13 phishing caught, +46 legit pages fixed — chosen deliberately
  from the curve, and every affected case sits in the soft SUSPICIOUS band, never a hard block.
- **The dampener** halves the score when the model is confidently safe (`prob < 0.3`), so a couple
  of weak structural coincidences on an obviously-safe URL don't add up to a false alarm.

---

## 4. The full rule/weight/threshold reference (`rules.json`)

### Scoring block
| Key | Value | Meaning |
|---|---|---|
| `ML_SAFE_THRESHOLD` | 0.35 | Below → model confidently safe |
| `ML_DECISION_THRESHOLD` | 0.60 | At/above → model predicts phishing |
| `W_BRAND` | 3.0 | Brand look-alike weight |
| `W_TYPO` | 3.0 | Typosquat weight |
| `W_SUBDOMAIN` | 3.0 | Brand-in-subdomain weight |
| `W_IP` | 2.5 | Raw-IP host weight |
| `W_PHISHTANK` | 4.0 | (legacy; blocklist is now a decisive gate, not this weight) |
| `W_KEYWORD` | 1.5 | Phishing-keyword weight (gated on `prob ≥ KEYWORD_MIN_PROB`) |
| `KEYWORD_MIN_PROB` | 0.55 | Model must lean phishing before keywords add |
| `W_NEW_DOMAIN` | 1.0 | Domain < 30 days old (optional WHOIS) |
| `W_NO_SSL` | 0.5 | SSL invalid (mild — modern phishing has valid certs) |
| `DAMPENER_THRESHOLD` | 0.3 | Below this prob, halve the score |
| `T_PHISHING` | 4.5 | Score ≥ → PHISHING |
| `T_SUSPICIOUS` | 3.0 | Score ≥ → SUSPICIOUS |

### Lists
- **brands** (32), **keywords** (41), **suspicious_tlds** (19), **trusted_roots** (~245),
  **shared_hosting_roots** (7) — enumerated in [02_ARCHITECTURE_FILE_BY_FILE.md](02_ARCHITECTURE_FILE_BY_FILE.md#a5-backendrulesjson--the-tunable-data-no-code-change-to-edit).

### Network / limits
- WHOIS timeout 4 s, SSL timeout 5 s, cache TTL 900 s.
- MAX_URL_LEN 2048, NEW_DOMAIN_MAX_AGE_DAYS 30, RECENT_MAX_LIMIT 200.

---

## 5. Worked examples (how a URL flows through the gates)

| URL | Where it resolves | Verdict |
|---|---|---|
| `http://192.168.0.5/login` | Gate 2 (raw IP → structural-critical) | PHISHING 10.0 |
| `http://paypal.com@evil.xyz/` | Gate 2 (`@` in authority) | PHISHING 10.0 |
| `xn--pypal-4ve.com` (Cyrillic paypal) | Gate 2 (corroborated brand spoof: feat8 + feat20/21) | PHISHING 10.0 |
| a URL on the OpenPhish blocklist | Gate 2b | PHISHING 9.0 |
| `evil-page.github.io` (blocklisted) | Gate 2b (shared-host carve-out overrides allowlist) | PHISHING 9.0 |
| `google.com/anything` | Gate 2c (trusted root) | SAFE |
| `microsoft.github.io/monaco-editor/` | Gate 2c (allowlist integrity) | SAFE |
| `openai.com` (model prob 0.05, no flags) | Gate 3 (confident-safe) | SAFE |
| `secure-login-update.tk/verify` (prob 0.7, TLD+keyword) | Gate 4 (score ≥ 4.5) | PHISHING |
| `some-shop.com/account` (prob 0.5) | Gate 4 (keyword gated out at 0.55, score < 3.0) | SAFE |

---

## 6. How the risk score maps to the verdict (the 0–10 scale)

- **Gate 2** → 10.0 (structural certainty).
- **Gate 2b** → 9.0 (known-bad blocklist).
- **Gate 2c / Gate 3** → ~0 (trusted / confidently safe).
- **Gate 4** → computed 0–10 score, thresholded at 4.5 (PHISHING) and 3.0 (SUSPICIOUS).

So the score isn't just the model probability — it's a **fusion** of the calibrated probability
(scaled ×3) and weighted structural evidence, with hard overrides pinned to the top of the scale.
This gives users an intuitive severity number *and* a defensible verdict.

---

## 7. Why this specific design is defensible

- **Model-first**, so it generalizes to novel phishing rather than only matching known patterns.
- **Overrides only for certainties** (IP, `@`, corroborated spoof) — never a vague heuristic
  masquerading as a hard block.
- **Allowlist and blocklist encode external truth** the model structurally can't know, with a
  carefully reasoned precedence (allowlist wins, except shared-hosting commons where a blocklist hit
  wins, never for real brands).
- **Every threshold is measured, not guessed** — the 0.60 decision line, the 0.55 keyword gate, and
  the 4.5/3.0 score cutoffs each have an experiment behind them in
  [`MODEL_AUDIT.md`](../MODEL_AUDIT.md).

Next: [05_CHROME_EXTENSION.md](05_CHROME_EXTENSION.md) — the browser extension from basics.
