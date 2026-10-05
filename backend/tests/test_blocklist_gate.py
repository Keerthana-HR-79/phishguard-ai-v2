"""
Locks the v3.0 decisive-blocklist gate (Gate 2b in main.predict_url_endpoint):

  * an exact known-phishing blocklist match forces PHISHING, and
  * it is evaluated BEFORE the Gate-3 confident-safe fast path (the bug this
    fixed: a benign-looking blocklisted URL used to return SAFE because the
    blocklist was only consulted in Gate 4, after Gate 3 had already exited), but
  * the trusted-root ALLOWLIST still wins over the blocklist — EXCEPT for the
    shared-hosting commons (v3.0.1): on github.io / *.tumblr.com / ... the
    blocklist overrides the allowlist, because those roots host third-party
    content (trust is in the platform, not the tenant), while real-brand roots
    (google.com) stay absolutely trusted so a stale feed entry can't flip them.
  * an allowlist hit that SURVIVES the blocklist short-circuits to SAFE at
    Gate 2c (v3.0.2), so the Gate-4 brand/subdomain heuristics can no longer
    flag a legit page on a trusted root (microsoft.github.io) as SUSPICIOUS.

This tests the endpoint's gate ORDERING in isolation: predict_ml, the network
helpers and log_event are stubbed, so the verdict depends only on the routing
logic — not on model weights or on volatile live-feed / DB contents.
"""
import asyncio
import pytest
import main

_URL = "https://zzq-neutral-4821.example/home"   # non-brand, non-allowlisted
# A URL on a shared-hosting commons root (tumblr.com ∈ SHARED_HOSTING_ROOTS).
# Deliberately brand-substring-free so the Gate-3/Gate-4 path is unambiguous.
_SHARED_HOST_URL = "https://some-user.tumblr.com/login"
_BRAND_URL       = "https://google.com/account/login"   # real brand, must stay trusted
# An allowlisted trusted root whose host ALSO reads as a brand-in-subdomain
# trick: real Microsoft project page on github.io. Without Gate 2c the Gate-4
# brand+subdomain heuristics push it to SUSPICIOUS (W_BRAND+W_SUBDOMAIN, dampened,
# lands just over T_SUSPICIOUS). Uses the REAL check_* helpers + BRANDS.
_ALLOWLIST_BRAND_SUBDOMAIN_URL = "https://microsoft.github.io/monaco-editor/"


@pytest.fixture(autouse=True)
def _stub_side_effects(monkeypatch):
    async def _age(_domain): return -1
    async def _ssl(_domain): return True
    monkeypatch.setattr(main, "_age_async", _age)
    monkeypatch.setattr(main, "_ssl_async", _ssl)
    monkeypatch.setattr(main, "log_event", lambda *a, **k: None)


def _verdict(url):
    return asyncio.run(main.predict_url_endpoint(main.URLRequest(url=url)))


def test_confident_safe_and_not_blocklisted_is_safe(monkeypatch):
    """Baseline: model confident-safe + not on blocklist → SAFE (Gate 3)."""
    monkeypatch.setattr(main, "predict_ml", lambda u: (0, 0.01, None))
    monkeypatch.setattr(main, "check_blocklist", lambda u: False)
    assert _verdict(_URL)["result"] == "SAFE"


def test_blocklist_match_forces_phishing_over_confident_safe(monkeypatch):
    """Same confident-safe model verdict, but ON the blocklist → PHISHING.
    Proves Gate 2b runs before the Gate-3 fast path."""
    monkeypatch.setattr(main, "predict_ml", lambda u: (0, 0.01, None))
    monkeypatch.setattr(main, "check_blocklist", lambda u: True)
    r = _verdict(_URL)
    assert r["result"] == "PHISHING"
    assert any("blocklist" in x.lower() for x in r["reasons"])


def test_allowlist_beats_blocklist(monkeypatch):
    """A trusted-root SAFE (non-None override_reason) must win even if the URL
    is 'on the blocklist' — Gate 2b is gated on override_reason is None."""
    monkeypatch.setattr(main, "predict_ml", lambda u: (0, 0.001, "Globally trusted domain"))
    monkeypatch.setattr(main, "check_blocklist", lambda u: True)
    assert _verdict(_URL)["result"] == "SAFE"


# ── v3.0.1: shared-hosting carve-out ─────────────────────────────────────────

def test_shared_host_allowlisted_blocklist_forces_phishing(monkeypatch):
    """A blocklisted URL on a shared-hosting commons root (tumblr.com) → PHISHING
    even though the root is allowlisted. Trust is in the platform, not the tenant."""
    monkeypatch.setattr(main, "predict_ml", lambda u: (0, 0.001, "Globally trusted domain"))
    monkeypatch.setattr(main, "check_blocklist", lambda u: True)
    r = _verdict(_SHARED_HOST_URL)
    assert r["result"] == "PHISHING"
    assert any("blocklist" in x.lower() for x in r["reasons"])
    assert any("shared-hosting" in x.lower() for x in r["reasons"])


def test_shared_host_allowlisted_not_blocklisted_stays_safe(monkeypatch):
    """A legit page on a shared-hosting root is never on the blocklist, so the
    allowlist keeps it SAFE — the carve-out only touches exact blocklist hits."""
    monkeypatch.setattr(main, "predict_ml", lambda u: (0, 0.001, "Globally trusted domain"))
    monkeypatch.setattr(main, "check_blocklist", lambda u: False)
    assert _verdict(_SHARED_HOST_URL)["result"] == "SAFE"


def test_real_brand_allowlisted_blocklist_stays_safe(monkeypatch):
    """A real-brand root (google.com) is NOT shared-hosting, so even a (stale)
    blocklist match must NOT flip it — brand roots stay absolutely trusted."""
    monkeypatch.setattr(main, "predict_ml", lambda u: (0, 0.001, "Globally trusted domain"))
    monkeypatch.setattr(main, "check_blocklist", lambda u: True)
    assert _verdict(_BRAND_URL)["result"] == "SAFE"


def test_localhost_blocklist_not_flipped(monkeypatch):
    """Localhost (a non-None, non-allowlist override) must never be flipped by a
    blocklist match — only the allowlist ('Globally trusted domain') is carved out."""
    monkeypatch.setattr(main, "predict_ml", lambda u: (0, 0.001, "Localhost dev environment"))
    monkeypatch.setattr(main, "check_blocklist", lambda u: True)
    assert _verdict("http://localhost:8000/login")["result"] == "SAFE"


# ── v3.0.2: allowlist survives the blocklist → SAFE (Gate 2c) ────────────────

def test_allowlisted_non_blocklisted_is_safe(monkeypatch):
    """An allowlisted root that isn't on the blocklist returns SAFE, carrying the
    trusted-domain override reason (Gate 2c)."""
    monkeypatch.setattr(main, "predict_ml", lambda u: (0, 0.001, "Globally trusted domain"))
    monkeypatch.setattr(main, "check_blocklist", lambda u: False)
    r = _verdict(_BRAND_URL)
    assert r["result"] == "SAFE"
    assert any("trusted" in x.lower() for x in r["reasons"])


def test_allowlisted_brand_subdomain_url_is_safe_not_suspicious(monkeypatch):
    """Regression for the microsoft.github.io FP: an allowlisted trusted root
    whose host also LOOKS like a brand-in-subdomain trick must return SAFE via
    Gate 2c — NOT SUSPICIOUS via Gate 4. The second half proves the guard has
    teeth: the SAME URL, treated as a non-allowlisted host, DOES trip the real
    brand+subdomain heuristics, so it is Gate 2c (not some other path) that
    keeps the allowlisted case safe."""
    monkeypatch.setattr(main, "check_blocklist", lambda u: False)
    monkeypatch.setattr(main, "predict_ml", lambda u: (0, 0.001, "Globally trusted domain"))
    assert _verdict(_ALLOWLIST_BRAND_SUBDOMAIN_URL)["result"] == "SAFE"
    monkeypatch.setattr(main, "predict_ml", lambda u: (0, 0.001, None))
    assert _verdict(_ALLOWLIST_BRAND_SUBDOMAIN_URL)["result"] == "SUSPICIOUS"
