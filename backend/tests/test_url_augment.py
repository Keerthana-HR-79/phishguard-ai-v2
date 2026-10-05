"""
Locks the url_augment helpers used by both training decorrelation and the
registrable-root logic (which mirrors predict_ml_only's trusted-root match).
"""
import random

from url_augment import registrable_domain, has_path, strip_to_host, add_path


def test_registrable_domain_basic_and_two_part_tld():
    assert registrable_domain("https://www.google.com/x") == "google.com"
    assert registrable_domain("https://sub.example.com") == "example.com"
    assert registrable_domain("https://byjus.com") == "byjus.com"
    # two-part public suffix keeps three labels
    assert registrable_domain("https://a.b.co.uk/path") == "b.co.uk"
    # credential '@' and port are stripped before extracting the root
    assert registrable_domain("http://legit.com@evil.com:8080/x") == "evil.com"


def test_has_path():
    assert has_path("https://x.com") is False
    assert has_path("https://x.com/") is False          # bare slash is not a path
    assert has_path("https://x.com/login") is True
    assert has_path("https://x.com/?q=1") is True        # query counts


def test_strip_to_host():
    assert strip_to_host("https://byjus.com/a/b?c=1") == "https://byjus.com"
    # missing scheme defaults to http
    assert strip_to_host("byjus.com/a") == "http://byjus.com"


def test_add_path_is_deterministic_with_seeded_rng_and_keeps_host():
    a = add_path("https://x.com", random.Random(0))
    b = add_path("https://x.com", random.Random(0))
    assert a == b                       # same seed -> same path
    assert a.startswith("https://x.com")
    # a different seed can differ, but must still hang off the same host
    c = add_path("https://x.com", random.Random(12345))
    assert c.startswith("https://x.com")
