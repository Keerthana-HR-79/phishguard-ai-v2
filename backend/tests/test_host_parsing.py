"""
Phase-1 host-parsing security hardening (backend v3.1.0). Locks three fixes so
they can't silently regress:

  H1  the loopback short-circuit keys on the PARSED HOST, not a substring of the
      whole URL — so http://evil.tk/localhost can no longer force a SAFE verdict.
  M1  the raw-IP structural override keys on the host being an IP literal, not on
      a dotted quad appearing anywhere in the URL (a '/v1.2.3.4/' version path is
      not a raw-IP host).
  M2  scheme detection is a real '<scheme>://' test, so a scheme-less
      http-prefixed host ('httpbin.org', 'http-login.tk') still parses its host
      instead of dropping it into the path (empty netloc, all host features 0).

The config-helper tests need no model; the predict_ml tests load model.pkl
(tests/conftest.py chdir's to backend/ so the CWD-relative load works).
"""
import pytest

from config import ensure_scheme, parse_host, host_is_ip, host_is_loopback


# ── config helpers (pure unit) ────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("https://x.com/a", "https://x.com/a"),          # real scheme kept
    ("http://x.com", "http://x.com"),
    ("ftp://h/x", "ftp://h/x"),                       # any real scheme kept
    ("x.com", "http://x.com"),                        # bare host gets http://
    ("httpbin.org", "http://httpbin.org"),           # M2: 'http'-prefixed, no '://'
    ("http-login.tk/a", "http://http-login.tk/a"),   # M2
    ("httpsecure.net", "http://httpsecure.net"),     # M2
])
def test_ensure_scheme(raw, expected):
    assert ensure_scheme(raw) == expected


@pytest.mark.parametrize("url,host", [
    ("https://www.paypal.com/login", "paypal.com"),      # www + scheme stripped
    ("http://user:pass@evil.com:8080/x", "evil.com"),    # userinfo + port stripped
    ("httpbin.org/get", "httpbin.org"),                  # M2 scheme-less
    ("http://[2001:db8::1]:443/x", "2001:db8::1"),       # IPv6 literal unwrapped
    ("http://127.0.0.1:8000", "127.0.0.1"),
])
def test_parse_host(url, host):
    assert parse_host(url) == host


@pytest.mark.parametrize("host,is_ip", [
    ("45.33.32.156", True),
    ("2001:db8::1", True),
    ("::1", True),
    ("paypal.com", False),
    ("v1.2.3.4", False),        # version string, not a valid IP literal
    ("", False),
])
def test_host_is_ip(host, is_ip):
    assert host_is_ip(host) is is_ip


@pytest.mark.parametrize("host,loop", [
    ("localhost", True),
    ("127.0.0.1", True),
    ("127.0.0.5", True),        # all of 127.0.0.0/8 is loopback
    ("::1", True),
    ("paypal.com", False),
    ("notlocalhost.com", False),  # exact host match, not substring
    ("", False),
])
def test_host_is_loopback(host, loop):
    assert host_is_loopback(host) is loop


# ── H1 / M1: predict_ml override behaviour (loads model.pkl) ───────────────────

from predict_ml_only import predict_ml   # noqa: E402  (after conftest chdir)

_LOOPBACK = "Localhost dev environment"
_CRITICAL = "Critical: Structural security risk detected"


@pytest.mark.parametrize("url", [
    "http://localhost:8000/app",
    "http://127.0.0.1:5000/login",
    "http://127.0.0.5/x",
    "https://[::1]/x",
])
def test_real_loopback_is_localhost_override(url):
    """A genuine loopback HOST still short-circuits to the dev-environment SAFE."""
    assert predict_ml(url)[2] == _LOOPBACK


@pytest.mark.parametrize("url", [
    "http://paypal-verify.tk/localhost/login",   # 'localhost' only in the path
    "http://evil.example/127.0.0.1/secure",      # loopback IP only in the path
])
def test_loopback_token_in_path_is_not_loopback_override(url):
    """H1: the whole-URL substring bypass is closed — a loopback token in the
    PATH must not short-circuit to the loopback SAFE override."""
    assert predict_ml(url)[2] != _LOOPBACK


def test_localhost_bypass_url_is_actively_flagged():
    """The classic bypass payload (http://<brand-spoof>/localhost/login) is now
    caught as a structural risk, not waved through."""
    pred, _prob, reason = predict_ml("http://paypal-verify.tk/localhost/login")
    assert pred == 1
    assert reason == _CRITICAL


@pytest.mark.parametrize("url", [
    "http://45.33.32.156/login",   # raw IPv4 host
    "http://192.168.0.1/admin",    # raw IPv4 host (non-loopback)
])
def test_raw_ip_host_is_critical_override(url):
    pred, _prob, reason = predict_ml(url)
    assert pred == 1
    assert reason == _CRITICAL


@pytest.mark.parametrize("url", [
    "http://cdn-assets.example/v1.2.3.4/app.js",            # dotted quad in PATH
    "https://downloads.example/release/10.20.30.40/setup",  # dotted quad in PATH
])
def test_dotted_quad_in_path_is_not_raw_ip_override(url):
    """M1: a version-ish dotted quad in the path is not a raw-IP HOST, so it must
    not trip the 'Critical' raw-IP structural override. (The model may still
    judge the URL on its own merits — that is a separate decision.)"""
    assert predict_ml(url)[2] != _CRITICAL


# ── H1 end-to-end: the closed bypass reaches a non-SAFE verdict ───────────────

import asyncio   # noqa: E402


@pytest.fixture
def _stub_net(monkeypatch):
    """Stub the network + logging side effects and isolate from the live feed, so
    the endpoint verdict depends only on the real predict_ml + gate routing."""
    import main
    async def _age(_d): return -1
    async def _ssl(_d): return True
    monkeypatch.setattr(main, "_age_async", _age)
    monkeypatch.setattr(main, "_ssl_async", _ssl)
    monkeypatch.setattr(main, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(main, "check_blocklist", lambda u: False)
    return main


def test_localhost_bypass_endpoint_not_safe(_stub_net):
    """Full pipeline with the REAL predict_ml: the /localhost bypass URL must not
    come back SAFE — proves Gate 2 propagates the structural override to a
    PHISHING verdict rather than the old guaranteed SAFE short-circuit."""
    main = _stub_net
    r = asyncio.run(main.predict_url_endpoint(
        main.URLRequest(url="http://paypal-verify.tk/localhost/login")))
    assert r["result"] != "SAFE"
