# 08 — Resume Points & "Tell Me About a Project" Script

Exact, copy-paste-ready résumé bullets plus the spoken script for when an interviewer says "walk me
through a project." Every number here is real and defensible from
[MODEL_AUDIT.md](../MODEL_AUDIT.md) and the probes in [06_TESTING.md](06_TESTING.md).

---

## 1. The one-line project title (for the résumé header)

> **PhishGuard AI — Real-Time Phishing URL Detector** · Python, FastAPI, XGBoost, scikit-learn,
> Chrome Extension (MV3) · *Personal project*

---

## 2. Résumé bullets — pick 3–4

Recruiters skim. Lead with impact + a number, name the tech, imply the depth. Best first:

**★ Strongest (use these):**

- Built a **real-time phishing-URL detector** (calibrated **XGBoost** + 22 engineered features +
  character/word **TF-IDF**) served by a **FastAPI** API, achieving a **6.2% false-positive rate**
  across 80,000 legitimate URLs and **70% recall on novel phishing domains** the model never trained
  on.

- **Diagnosed and eliminated data leakage** that had inflated accuracy to a misleading 98%; re-split
  the data by **registrable domain (GroupShuffleSplit)** and fit all vectorizers on the training slice
  only, reporting an **honest, generalizable ~75%** — and built statistical probes to measure the
  model the *right* way.

- Designed a **model-first, 6-gate detection pipeline** combining ML probability with structural
  overrides, an OpenPhish/PhishTank blocklist, and a trusted-domain allowlist — cutting false
  positives on legitimate brand pages while forcing hard blocks only on structural certainties
  (raw-IP hosts, credential-`@` tricks, corroborated brand spoofs).

- Improved the model across **5 gated retrains** (false-positive rate **10.4% → 6.2%**, recall at
  equal FP **~25% → 61%**), with every retrain **backed up and shipped only if it cleared a 9.7%
  false-positive ceiling** — making "it kept getting better" a verifiable claim.

**★ Also strong (swap in as space allows):**

- Shipped a **Manifest V3 Chrome extension** that checks every visited page against the same API and
  injects a warning banner — and **fixed two security bugs** in it (a CSP-violating `new Function()`
  and a DOM-XSS `innerHTML` sink) using `chrome.scripting` + `textContent`.

- Wrote a **128-case pytest regression suite** plus large-scale statistical probes (false-positive
  sweep, equal-FP recall, cross-source recall), separating fast behavioral contracts from model-
  quality metrics.

- Hardened a hostile-input system: **parsed-host** security checks (not substring matching), URL
  de-fanging, CSV formula-injection guards on the analytics export, and env-var secret handling.

- Deployed as a full stack — **FastAPI on Render, static frontend on Vercel**, SQLite event logging,
  and a **Power BI star-schema** analytics export.

---

## 3. Skills this project lets you list (honestly)

- **Machine Learning:** supervised classification, XGBoost/gradient boosting, feature engineering,
  TF-IDF, probability calibration, **data-leakage detection**, model evaluation (precision/recall,
  FP/recall tradeoffs), reproducible training.
- **Backend:** Python, FastAPI, async request handling, Pydantic validation, REST API design.
- **Data:** dataset assembly (~1.5M rows), SQLite, star-schema modeling, Power BI.
- **Frontend/Browser:** vanilla JS, Chrome Extension (Manifest V3), service workers.
- **Engineering practice:** pytest, regression testing, security hardening, Git, CI-style gating,
  cloud deployment (Render, Vercel).

---

## 4. The "Tell me about a project" script (~90 seconds, spoken)

> "I built **PhishGuard**, a real-time phishing-URL detector. You give it a URL and it returns
> safe, suspicious, or phishing with a risk score — through a web app and a Chrome extension that
> checks pages automatically.
>
> The core is a **calibrated XGBoost model** on about 1.5 million URLs, using 22 hand-engineered
> features plus character and word TF-IDF — the character n-grams are what catch look-alikes like
> `paypa1` or a Cyrillic `paypal`.
>
> The part I'm proudest of: my first models hit **98% accuracy**, and I realized that was **data
> leakage** — I was splitting by row, so the same domain appeared in both train and test, and there
> was a 'URL has a path ⇒ phishing' artifact. I re-split **by registrable domain** so a domain is
> entirely in train or test, fit the vectorizers on the training slice only, and the honest number
> dropped to about **75%**. I'd rather ship a defensible 75% than a fake 98%.
>
> Because a URL-string model has blind spots, I wrapped it in a **model-first, 6-gate pipeline**: the
> model scores first, then structural certainties like a raw-IP host force a block, a live blocklist
> catches known-bad, and a trusted-domain allowlist protects real brands. I measure it with probes,
> not one accuracy number — a **6.2% false-positive rate over 80,000 legit URLs** and **70% recall on
> phishing domains it never trained on** — and every one of five retrains had to clear a false-
> positive ceiling to ship.
>
> It's deployed on Render and Vercel, has a 128-case regression suite, and I even fixed a couple of
> security bugs in the extension along the way."

**Then stop.** That script is engineered to make the interviewer ask about the leakage, the gates, or
XGBoost — all of which you can go deep on from [07_INTERVIEW_QA.md](07_INTERVIEW_QA.md).

---

## 5. The single strongest lines (memorize verbatim)

1. *"My first models hit 98%, but that was data leakage — I fixed the split to group by domain and
   reported an honest 75%."* — signals **maturity and rigor** more than any high number could.
2. *"The model runs first; the rules are a principled safety-net around it, not a pile of rules with
   ML bolted on."* — signals **system design**.
3. *"I don't report a single accuracy number — I measure false positives on 80k legit URLs and recall
   on phishing the model never saw, because those are the questions that matter operationally."* —
   signals **you think like an engineer, not a Kaggle scorer**.
4. *"Every retrain was backed up and only shipped if it cleared a 9.7% false-positive ceiling."* —
   signals **discipline and reproducibility**.

---

## 6. Honest framing rules (don't oversell)

- Call it a **personal project**, not production software with users.
- Say **~75% honest accuracy** and immediately give the *why* — never quote the 98%.
- The datasets are **public feeds** (Tranco, OpenPhish, PhishTank, Kaggle) — say so.
- It's **URL-string only** — if asked about page-content analysis, that's future work, not a claim.
- If asked "did anyone use it?" — it's deployed and functional; be honest that it's a portfolio
  project, not a product with a user base.

> The whole point of this project as an interview asset is that **it survives scrutiny**. Every claim
> here maps to a real file, a real number, or a real experiment. Lead with the leakage story, stay
> honest, and go as deep as they want — the depth is all in docs 01–06.

---

That's the full documentation set:
[README](README.md) ·
[01 Overview & Stack](01_OVERVIEW_AND_TECH_STACK.md) ·
[02 Architecture](02_ARCHITECTURE_FILE_BY_FILE.md) ·
[03 ML From Basics](03_MACHINE_LEARNING_FROM_BASICS.md) ·
[04 Rules & Detection](04_RULES_AND_DETECTION_LOGIC.md) ·
[05 Chrome Extension](05_CHROME_EXTENSION.md) ·
[06 Testing](06_TESTING.md) ·
[07 Interview Q&A](07_INTERVIEW_QA.md) ·
**08 Resume Points**
