"""
train_ml_strong.py  —  PhishGuard AI  v3.1
===========================================
Changes from v2.1 (see MODEL_AUDIT.md P0: A1, A2, A3, A4, C1, C2, C5):

  • TRAIN-TIME PATH DECORRELATION (fixes A1/A2, the biggest win).
    The old data taught the shortcut "URL has a path => phishing" (legit was
    mostly bare Tranco domains, phishing mostly pathed). We now emit EVERY
    training URL twice — once bare (scheme://host) and once with a path drawn
    from a shared PATH_POOL (url_augment) — for BOTH classes. Result: ~50% of
    each class is pathed, and the path *content* is drawn from an identical
    distribution regardless of label. "Has a path" and the specific path string
    can no longer predict the class; only the HOST can. Bare phishing hosts also
    address A4 (clean bare malicious domains were absent).

  • GROUPED SPLIT BY REGISTRABLE DOMAIN (fixes C1).
    train_test_split split by row, so the same domain (many rows) landed in both
    train and test — the model memorized domains and the held-out 98% was
    inflated. We now use GroupShuffleSplit on the registrable domain so no domain
    is shared across splits. The reported score is an honest generalization
    estimate.

  • DISJOINT 3-WAY TRAIN / CALIBRATE / TEST (fixes C2).
    Calibration used to be fit on the same X_test the report was computed on
    (leaky). Now calibration is fit on its own held-out slice, disjoint (by
    group) from both train and test.

  • NO PREPROCESSING LEAKAGE — vectorizers + scaler fit on TRAIN ONLY (v3.1 / M10).
    Previously the TF-IDF vectorizers and the StandardScaler were .fit_transform-ed
    on the FULL augmented set and only THEN was the grouped split taken. The base
    model was always trained on X_train alone, but the feature *transform* (char /
    word vocabulary + IDF, and the scaler mean/std) had seen the calibration and
    test slices — so the reported held-out score was mildly optimistic. We now take
    the grouped split on ROW INDICES first, fit the two vectorizers and the scaler
    on the TRAIN slice only, and .transform() the calibration and test slices. The
    test report is now leakage-free end to end. (Vocabulary is saturated at
    max_features long before the ~40% held-out rows would matter, so the shipped
    decision surface barely moves — but it is now honestly measured. Any shift is
    gated on fp_sweep.py <= 9.70%.)

  • DETERMINISTIC TRAINING (v3.1 / M11).
    XGBClassifier now pins random_state=SEED and n_jobs=1 so a retrain is
    bit-reproducible run to run (XGBoost's parallel histogram build is otherwise
    order-nondeterministic). This is what makes the golden model-only scores in
    tests/test_feature_weights.py a meaningful lock and every audit number
    reproducible.

  • Feature weighting (X_char*0.05, X_word*0.05, X_num*15) is UNCHANGED on
    purpose and is now applied through the single shared helper
    config.stack_features (v3.1 / H3), so the train side and the serve side
    (predict_ml_only.py) rebuild X with byte-identical weights and can never drift.

Run:
    python generate_adversarial.py      # regenerate broadened adversarial set first
    python train_ml_strong.py
"""

import os
import re
import random
import pickle
import numpy as np
import pandas as pd

from sklearn.model_selection   import GroupShuffleSplit
from sklearn.metrics           import classification_report, confusion_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing     import StandardScaler
from sklearn.calibration       import CalibratedClassifierCV
from xgboost                   import XGBClassifier

from features    import extract_features
from url_augment import strip_to_host, add_path, has_path, registrable_domain
from config      import TRUSTED_ROOTS, stack_features

# ── A5: label-noise controls ──────────────────────────────────────────────────
# URL shorteners and free-hosting providers share ONE registrable root across
# thousands of unrelated (and often malicious) sites, so "root => legitimate" is
# unreliable for them. Blanket-labeling them legit (they sit in Tranco) teaches
# the model wrong examples. We drop them from BOTH classes so no single-host
# signal is learned from an inherently mixed root.
NOISE_ROOTS = {
    # shorteners
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.ly", "tny.im",
    "clck.ru", "bl.ink", "shorte.st", "adf.ly",
    # free hosting / user-content subdomains (root shared by many sites)
    "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "wix.com",
    "000webhostapp.com", "github.io", "gitlab.io", "glitch.me", "herokuapp.com",
    "web.app", "firebaseapp.com", "netlify.app", "vercel.app", "pages.dev",
    "repl.co", "surge.sh", "neocities.org", "sites.google.com", "forms.gle",
    "s3.amazonaws.com", "storage.googleapis.com", "azurewebsites.net",
    "r2.dev", "workers.dev", "onrender.com", "duckdns.org", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com",
}


# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DATASET  = "../data/processed/final_dataset.csv"
LEGIT_DATASET = "../data/processed/legit_urls.csv"       # from build_legit_dataset.py
ADV_DATASET   = "../data/processed/adversarial_phishing.csv"
FRESH_DATASET = "../data/processed/fresh_phishing.csv"   # from harvest_fresh_data.py (optional)

# Raised 50k -> 150k in v3.3. harvest_fresh_data.py stages ~155k fresh,
# currently-active bare phishing domains — novel registrable roots that roughly
# TRIPLE unique phishing-root diversity and directly target the clean bare-domain
# recall gap. At the old 50k cap the random balance step would have sampled almost
# all of that new data back out, so the model would never see the new patterns.
# 150k lets a balanced blend of existing + fresh phishing (and an equal legit
# sample) reach training. Any decision-surface shift is gated on fp_sweep.py.
MAX_PER_CLASS = 150_000   # cap BEFORE augmentation; ×2 after (bare+pathed) => ~300k/class
SEED          = 42

# ── Load data ─────────────────────────────────────────────────────────────────
print("Loading datasets...")

base = pd.read_csv(BASE_DATASET)
adv  = pd.read_csv(ADV_DATASET)
# Adversarial phishing: 2× boost (was 20× before — that caused over-sensitivity)
adv_boosted = pd.concat([adv] * 2, ignore_index=True)

# The legit dataset (Tranco + seed + FP reports)
legit_extra = pd.read_csv(LEGIT_DATASET)
legit_extra["type"] = "legitimate"   # file only carries url+type; enforce it

# Fresh, currently-active bare phishing domains (harvest_fresh_data.py). OPTIONAL:
# if the file is absent the trainer behaves exactly as before. Each row is a novel
# registrable root staged as http://<root>, so the path-decorrelation augmentation
# emits a bare AND a pathed variant — the bare variant is exactly the clean
# bare-domain phishing signal the model was missing (limitation #2).
frames = [base, adv_boosted, legit_extra]
if os.path.exists(FRESH_DATASET):
    fresh = pd.read_csv(FRESH_DATASET)
    fresh["type"] = "phishing"                 # enforce label (file carries url+type)
    frames.insert(2, fresh)                    # after adv, before legit
    print(f"  + fresh phishing source : {len(fresh):,} rows ({FRESH_DATASET})")
else:
    print(f"  (no fresh phishing source at {FRESH_DATASET} — base+adv only)")

combined = pd.concat(frames, ignore_index=True)
combined = combined.dropna(subset=["url"])

phishing = combined[combined["type"] == "phishing"].copy()
legit    = combined[combined["type"] == "legitimate"].copy()

print(f"  Phishing before clean : {len(phishing):,}")
print(f"  Legit    before clean : {len(legit):,}")

# ── A5: clean host-level label noise BEFORE balancing ─────────────────────────
# A URL-lexical model judges by HOST, so a registrable root labeled phishing
# when it is really a curated-legit root (compromised page, open redirect, feed
# error) teaches the exact false positive the user reported (byjus.com/... ->
# phishing), and an unreliable shared-hosting root is pure noise. Two surgical
# rules remove the unambiguous label noise (a third, more aggressive rule was
# tried and reverted — see (c) below):
phishing["root"] = phishing["url"].astype(str).map(registrable_domain)
legit["root"]    = legit["url"].astype(str).map(registrable_domain)

# (a) A high-confidence-legit root (curated trusted_roots) must NEVER be a
#     phishing training example, whatever path a feed attached to it.
n = len(phishing)
phishing = phishing[~phishing["root"].isin(TRUSTED_ROOTS)]
print(f"  A5 (a): dropped {n - len(phishing):,} phishing rows on trusted roots")

# (b) Drop shortener / free-host roots from BOTH classes (root not reliably safe).
nl, np_ = len(legit), len(phishing)
legit    = legit[~legit["root"].isin(NOISE_ROOTS)]
phishing = phishing[~phishing["root"].isin(NOISE_ROOTS)]
print(f"  A5 (b): dropped {nl - len(legit):,} legit + {np_ - len(phishing):,} "
      f"phishing rows on shortener/free-host roots")

# (c) REMOVED in v3.2b after measurement. An earlier v3.2 also dropped every
#     phishing row whose root merely appeared somewhere in the legit set
#     (34,318 rows on 2,694 roots). That was too aggressive: it stripped out
#     legit-host-but-compromised phishing (real "clean host + phishing path"
#     examples), which shifted the phishing class toward hyphen/keyword
#     hostnames and recalibrated the 0.5 boundary upward — the model-only legit
#     false-positive rate rose 10.4% -> 13.8% on the 80k legit sweep, and the
#     NEW false positives were overwhelmingly clean-host + security-path URLs
#     (channel4.com/account, indiatoday.in/secure/checkout) — i.e. it made the
#     PATH artifact worse, the opposite of the goal. Rules (a) and (b) remove
#     the unambiguous label noise; the byjus-class clean roots are protected by
#     the trusted_roots allowlist at serving time, so (c) is not needed. Genuine
#     legit-root/phishing-path ambiguity is realistic signal and is kept.
#     GroupShuffleSplit already prevents any single root leaking across splits.

phishing = phishing.drop(columns=["root"])
legit    = legit.drop(columns=["root"])
print(f"  Phishing after clean  : {len(phishing):,}")
print(f"  Legit    after clean  : {len(legit):,}")

size     = min(len(phishing), len(legit), MAX_PER_CLASS)
phishing = phishing.sample(size, random_state=SEED)
legit    = legit.sample(size, random_state=SEED)


data = pd.concat([phishing, legit]).reset_index(drop=True)
data["label"] = (data["type"] == "phishing").astype(int)
print(f"  Balanced to {size:,} per class ({len(data):,} rows) before augmentation")

# ── Path-decorrelation augmentation (the core fix) ─────────────────────────────
# Emit each URL twice: once bare, once pathed. Same PATH_POOL for both classes,
# so path presence/content is independent of the label.
print("\nAugmenting: bare + pathed variant per URL (kills the path artifact)...")
rng = random.Random(123)
aug_urls, aug_labels = [], []
for u, lab in zip(data["url"].astype(str), data["label"].tolist()):
    bare = strip_to_host(u)
    if bare and "." in bare.split("//")[-1]:      # skip malformed hosts
        aug_urls.append(bare);            aug_labels.append(lab)
        aug_urls.append(add_path(u, rng)); aug_labels.append(lab)

aug = pd.DataFrame({"url": aug_urls, "label": aug_labels})
aug = aug.drop_duplicates("url").sample(frac=1, random_state=SEED).reset_index(drop=True)

# Sanity: pathed fraction should be ~50% for BOTH classes now.
for lab, name in [(0, "legitimate"), (1, "phishing")]:
    sub = aug[aug["label"] == lab]["url"]
    frac = sub.apply(has_path).mean() if len(sub) else 0.0
    print(f"    {name:<11} rows: {len(sub):>7,}   pathed: {frac*100:5.1f}%")

# ── Feature inputs (raw; NOT yet vectorized — no leakage across the split) ────
print("\nPreparing feature inputs (vectorizers fit AFTER the split)...")
original_urls = aug["url"].astype(str).reset_index(drop=True)
# Strip protocol — model must not cheat by memorising https vs http
text_urls = original_urls.apply(lambda x: re.sub(r"^https?://", "", x))
labels    = aug["label"].values
groups    = original_urls.apply(registrable_domain).values

# ── Grouped 3-way split by registrable domain, taken on ROW INDICES ───────────
# The split happens BEFORE any vectorizer/scaler is fit, so the char/word
# vocabulary + IDF and the scaler mean/std are learned from TRAIN rows only. The
# calibration and test slices are transform-only — never seen at fit time.
print("Splitting by registrable domain (grouped, leakage-free)...")
idx_all = np.arange(len(original_urls))

# 1) hold out TEST (20% of groups)
gss_test = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=SEED)
trainval_idx, test_idx = next(gss_test.split(idx_all, labels, groups))

# 2) from the rest, hold out CALIBRATION (20% of the remaining groups)
gss_cal = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=SEED)
rel_tr, rel_cal = next(gss_cal.split(trainval_idx, labels[trainval_idx], groups[trainval_idx]))
train_idx = trainval_idx[rel_tr]
cal_idx   = trainval_idx[rel_cal]

g_train, g_cal, g_test = set(groups[train_idx]), set(groups[cal_idx]), set(groups[test_idx])
assert g_train.isdisjoint(g_test),  "LEAKAGE: train/test share a domain"
assert g_train.isdisjoint(g_cal),   "LEAKAGE: train/calibrate share a domain"
assert g_cal.isdisjoint(g_test),    "LEAKAGE: calibrate/test share a domain"

# ── Fit vectorizers + scaler on TRAIN ONLY, then transform every slice ────────
print("\nExtracting text features (TF-IDF, fit on train slice only)...")
char_vec = TfidfVectorizer(max_features=3000, analyzer="char", ngram_range=(3, 5))
word_vec = TfidfVectorizer(max_features=1000)

train_text = text_urls.iloc[train_idx]
char_vec.fit(train_text)
word_vec.fit(train_text)

print("Extracting numerical features (scaler fit on train slice only)...")
X_num_all = np.array([extract_features(u) for u in original_urls])
scaler = StandardScaler()
scaler.fit(X_num_all[train_idx])


def _build(slice_idx):
    """Transform one slice with the train-fit vectorizers/scaler and stack it
    with the exact serving weights (config.stack_features)."""
    txt = text_urls.iloc[slice_idx]
    Xc  = char_vec.transform(txt)
    Xw  = word_vec.transform(txt)
    Xn  = scaler.transform(X_num_all[slice_idx])
    return stack_features(Xc, Xw, Xn)


X_train, y_train = _build(train_idx), labels[train_idx]
X_cal,   y_cal   = _build(cal_idx),   labels[cal_idx]
X_test,  y_test  = _build(test_idx),  labels[test_idx]

print(f"  train: {X_train.shape[0]:>7,} rows / {len(g_train):>6,} domains")
print(f"  calib: {X_cal.shape[0]:>7,} rows / {len(g_cal):>6,} domains")
print(f"  test : {X_test.shape[0]:>7,} rows / {len(g_test):>6,} domains  (all disjoint)")

# ── Train base model ──────────────────────────────────────────────────────────
print("\nTraining XGBoost...")
base_model = XGBClassifier(
    n_estimators=400,
    max_depth=7,
    learning_rate=0.05,
    scale_pos_weight=1,      # dataset is balanced 50/50
    eval_metric="logloss",
    random_state=SEED,       # M11: reproducible run to run
    n_jobs=1,                # M11: serial build => deterministic (no thread-order noise)
    verbosity=0,
)
base_model.fit(X_train, y_train)

print("\n=== Raw model performance (held-out TEST, grouped) ===")
raw_preds = base_model.predict(X_test)
print(classification_report(y_test, raw_preds, target_names=["legitimate", "phishing"]))

# ── Probability calibration on the DISJOINT calibration slice ──────────────────
print("Calibrating probabilities (isotonic) on the held-out calibration split...")
model = CalibratedClassifierCV(base_model, cv="prefit", method="isotonic")
model.fit(X_cal, y_cal)      # <-- disjoint from both train and test (fixes C2)

print("\n=== Calibrated model performance (held-out TEST, grouped) ===")
cal_preds = model.predict(X_test)
print(classification_report(y_test, cal_preds, target_names=["legitimate", "phishing"]))
cm = confusion_matrix(y_test, cal_preds)
print("  confusion matrix [rows=true, cols=pred] (legit, phishing):")
print(f"    legit    -> {cm[0].tolist()}")
print(f"    phishing -> {cm[1].tolist()}")
print("  NOTE: this is an HONEST grouped, model-only score — not the old,")
print("        leakage-inflated ~98%. See MODEL_AUDIT.md C1/C5.")

# ── Save artifacts ────────────────────────────────────────────────────────────
print("\nSaving model artifacts...")
pickle.dump(model,    open("model.pkl",            "wb"))
pickle.dump(char_vec, open("char_vectorizer.pkl",  "wb"))
pickle.dump(word_vec, open("word_vectorizer.pkl",  "wb"))
pickle.dump(scaler,   open("scaler.pkl",           "wb"))

print("[OK] All artifacts saved.")
print()
print("Next steps:")
print("  1. python model_stress_test.py     # before/after on a realistic mix")
print("  2. python path_artifact_probe.py    # confirm bare vs +path no longer flips")
print("  3. uvicorn main:app --reload        # spot-check via /predict_url")
