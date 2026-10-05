"""
Locks the invariants of config.py / rules.json that the whole engine depends on:
the trusted-root allowlist, the brand list feeding the model features, the
threshold ordering, and the strip_www prefix-strip bug-fix.
"""
import config


def test_trusted_roots_is_lowercase_set_with_key_domains():
    tr = config.TRUSTED_ROOTS
    assert isinstance(tr, (set, frozenset))
    assert len(tr) > 100                      # curated allowlist (~245)
    assert all(d == d.lower() for d in tr)    # every root normalized lowercase
    # The specific roots that fixed reported false positives must stay present.
    for d in ("google.com", "byjus.com", "byjusexamprep.com"):
        assert d in tr, f"{d} missing from trusted_roots"


def test_brands_and_keywords_nonempty_lowercase():
    assert config.BRANDS and all(b == b.lower() for b in config.BRANDS)
    assert config.KEYWORDS and all(k == k.lower() for k in config.KEYWORDS)
    # Brands the typo/homograph tests rely on.
    assert "google" in config.BRANDS
    assert "paypal" in config.BRANDS


def test_suspicious_tlds_lowercase_no_leading_dot():
    tlds = config.SUSPICIOUS_TLDS
    assert tlds
    assert all(t == t.lower() and not t.startswith(".") for t in tlds)


def test_threshold_ordering():
    # SAFE fast-path must be stricter than the decision boundary.
    assert 0.0 < config.ML_SAFE_THRESHOLD < config.ML_DECISION_THRESHOLD <= 1.0
    # Decision boundary raised 0.5 -> 0.6 in v3.3: the fresh-data retrain moved the
    # recall/FP frontier, so 0.6 holds the model-only legit FP rate BELOW the v3.2b
    # baseline (6.4% vs 9.7%) while still gaining bare-domain recall (see
    # operating_point.py / MODEL_AUDIT.md v3.3). It also keeps every byjus deep-path
    # below threshold at the model level again.
    assert config.ML_DECISION_THRESHOLD == 0.6
    # Heuristic bands ordered.
    assert config.T_SUSPICIOUS < config.T_PHISHING


def test_keyword_min_prob_operating_point():
    # The keyword heuristic bump (W_KEYWORD=+1.5) only corroborates once the
    # model already leans phishing. KEYWORD_MIN_PROB was raised 0.40 -> 0.55
    # (backend v2.9) so ordinary legit pages (/login, /account, /secure/checkout)
    # on non-allowlisted hosts stop crossing the SUSPICIOUS line on the keyword
    # alone. It MUST sit strictly between the SAFE fast-path and the decision
    # line — below the fast-path it can never fire, at/above the decision line it
    # only ever fires on URLs the model already flags. Chosen from the measured
    # recall/FP curve in keyword_rule_probe.py; see MODEL_AUDIT.md
    # "v2.9 — Keyword-rule operating point".
    assert config.KEYWORD_MIN_PROB == 0.55
    assert config.ML_SAFE_THRESHOLD < config.KEYWORD_MIN_PROB < config.ML_DECISION_THRESHOLD


def test_strip_www_is_a_true_prefix_strip():
    # The classic str.lstrip('www.') bug would turn whatsapp -> hatsapp.
    assert config.strip_www("www.whatsapp.com") == "whatsapp.com"
    assert config.strip_www("WWW.Example.COM") == "example.com"
    assert config.strip_www("wallet.com") == "wallet.com"   # not a www. prefix
    assert config.strip_www("nowww.org") == "nowww.org"
