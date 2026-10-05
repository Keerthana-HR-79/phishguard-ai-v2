"""
Locks the main.py request-path helpers: input de-fanging / slash-collapse
(the byjus-many-slashes fix + threat-intel de-fang), domain extraction, and the
typo/subdomain brand heuristics that back-stop the model.
"""
import main


def test_normalize_url_defangs_threat_intel_notation():
    assert main._normalize_url("hxxp://evil[.]com") == "http://evil.com"
    assert main._normalize_url("http://evil[dot]com") == "http://evil.com"
    assert main._normalize_url("hxxps://a[.]b[.]com") == "https://a.b.com"


def test_normalize_url_collapses_redundant_slashes_but_keeps_scheme():
    # The reported byjus regression: many slashes inflated URL features.
    assert main._normalize_url("https://byjus.com//////login") == "https://byjus.com/login"
    # scheme's own '://' must be preserved.
    assert main._normalize_url("https://byjus.com").startswith("https://")


def test_normalize_url_trims_and_caps_length():
    assert main._normalize_url("  https://x.com  ") == "https://x.com"
    long = "http://a.com/" + "a" * 5000
    assert len(main._normalize_url(long)) <= 2048


def test_extract_domain_strips_www_port_and_credential_at():
    assert main.extract_domain("https://www.byjus.com/x") == "byjus.com"
    assert main.extract_domain("http://byjus.com:8443/x") == "byjus.com"
    # credential '@' trick: the real host is to the right of '@'.
    assert main.extract_domain("http://paypal.com@evil.com/login") == "evil.com"


def test_levenshtein():
    assert main.levenshtein("kitten", "sitting") == 3
    assert main.levenshtein("abc", "abc") == 0
    assert main.levenshtein("", "abc") == 3


def test_check_typo_catches_one_edit_squats_only():
    assert main.check_typo("gogle.com")[0] is True      # google, 1 deletion
    assert main.check_typo("paypa1.com")[0] is True     # paypal, 1 substitution
    assert main.check_typo("google.com")[0] is False    # exact brand, not a typo
    assert main.check_typo("example.com")[0] is False   # unrelated


def test_check_subdomain_flags_brand_in_subdomain():
    assert main.check_subdomain("http://paypal.evil.com/login")[0] is True
    assert main.check_subdomain("http://google.com")[0] is False
    assert main.check_subdomain("http://shop.example.com")[0] is False
