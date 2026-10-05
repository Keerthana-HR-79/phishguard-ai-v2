"""
Locks the feature-block weight invariant and the train/serve feature pipeline.

Background (H3): the weight triple that scales the three feature blocks before
they are concatenated for the model — char-TF-IDF * 0.05, word-TF-IDF * 0.05,
numeric * 15 — used to be hand-copied into ~12 files (every probe, the trainer,
and the serving path). A single drifting copy silently breaks train/serve
consistency: the model is trained on one geometry and scored on another, which
degrades every verdict with no error. config.FEATURE_WEIGHTS +
config.stack_features() are now the single source of truth; these tests fail if
anyone reintroduces a divergent literal or changes the shipped weights without
updating this lock.

They also pin, as golden values:
  * the 22-length feature vector extract_features() returns for a fixed URL (M9),
    so a change to feature ORDER, COUNT, or computation is caught; and
  * the model-only phishing score for fixed URLs, which locks the trained model
    artifacts (model.pkl + the two vectorizers + scaler) TOGETHER with the
    stacking geometry — if a retrain ships or the weights move, this trips and
    forces a conscious re-baseline (and a re-check of the 9.70% FP gate).
"""
import numpy as np
import pytest
from scipy.sparse import csr_matrix

import config
from features import extract_features
from homograph_probe import model_only


# ── H3: the weight triple is the single source of truth ─────────────────────
def test_feature_weights_value():
    # (char_tfidf, word_tfidf, numeric). These are a train/serve invariant:
    # the model was fit with exactly this geometry.
    assert config.FEATURE_WEIGHTS == (0.05, 0.05, 15)


def test_stack_features_applies_weights_and_concatenates():
    # Tiny known blocks: one row, easy-to-verify values.
    xc = csr_matrix(np.array([[1.0, 2.0]]))      # char block, 2 cols
    xw = csr_matrix(np.array([[4.0]]))           # word block, 1 col
    xn = csr_matrix(np.array([[1.0, 3.0]]))      # numeric block, 2 cols

    stacked = config.stack_features(xc, xw, xn)
    # csr, single row, blocks concatenated left-to-right in (char, word, num) order.
    assert stacked.shape == (1, 5)
    dense = stacked.toarray()[0].tolist()
    wc, ww, wn = config.FEATURE_WEIGHTS
    assert dense == [1.0 * wc, 2.0 * wc, 4.0 * ww, 1.0 * wn, 3.0 * wn]


def test_stack_features_returns_csr():
    xc = csr_matrix(np.zeros((1, 1)))
    out = config.stack_features(xc, xc, xc)
    # Serving calls model.predict_proba on the result; csr is the format the
    # model was trained on and the format predict paths assume.
    assert out.getformat() == "csr"


# ── M9: golden 22-vector locks feature order / count / computation ──────────
def test_extract_features_golden_vector():
    url = "http://secure-login-paypal-verify.com/account/update"
    vec = extract_features(url)
    assert len(vec) == 22, "feature count must stay 22 (model input width)"
    golden = [
        0.52, 1.0, 3.0, 4.0, 0.0, 4.310735, 5.0, 1.0,
        1.0, 1.0, 0.0, 0.0, 0.0, 2.0, 1.0, 0.0,
        0.0, 0.0, 3.0, 3.0, 0.0, 0.0,
    ]
    got = [float(x) for x in vec]
    assert got == pytest.approx(golden, abs=1e-4), (
        "extract_features drifted — feature order, count, or a computation "
        "changed. If this is intentional, retrain (feature width/order feeds "
        "the model) and re-baseline this golden vector."
    )


# ── H3 + artifacts: golden model-only scores lock train/serve together ──────
@pytest.mark.parametrize("url,golden", [
    # obvious lexical phish, keyword-stacked authority -> saturates high
    ("http://secure-login-paypal-verify.com/account/update", 1.0000000000),
    # plain, unknown domain with a benign path -> mid/high soft score
    ("http://plain-shopfront-example.com/products/item/42", 0.8527496457),
    # short bare unknown domain -> below the 0.6 decision line
    ("http://zerodha.com", 0.3206036389),
])
def test_model_only_golden_scores(url, golden):
    # model_only rebuilds X exactly like serving (stack_features) and scores the
    # shipped artifacts. A drift here means either the weights moved, the feature
    # pipeline changed, or the model was retrained — all of which must go through
    # the FP gate (fp_sweep.py <= 9.70%) and a conscious re-baseline of these values.
    # Values above are for the v3.1-trainer model (deterministic: n_jobs=1 +
    # random_state, no preprocessing leakage) shipped in Phase 5.
    assert model_only(url) == pytest.approx(golden, abs=1e-6)
