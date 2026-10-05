"""
Locks the extract_features() contract. The 22-length vector and the exact
meaning of the security-critical indices are a serving invariant shared by
train / predict / every probe — a silent change here corrupts the model input.
"""
import pytest

from features import extract_features
from config import SUSPICIOUS_TLDS

# Cyrillic 'a' (U+0430) — renders like ASCII 'a' but is a different codepoint.
CYRILLIC_A = "а"


@pytest.mark.parametrize("url", [
    "http://example.com",
    "https://www.google.com/some/deep/path?q=1",
    "",                                   # empty
    None,                                 # None -> str(None)
    "http://",                            # no host
    "not a url with spaces",              # garbage
    "http://xn--pple-43d.com",            # punycode
    f"http://{CYRILLIC_A}pple.com",       # raw non-ASCII host
    "http://" + "a" * 5000 + ".com",      # pathological length
])
def test_feature_vector_is_always_length_22(url):
    feats = extract_features(url)
    assert isinstance(feats, list)
    assert len(feats) == 22


def test_ip_host_flag_feat10():
    assert extract_features("http://45.12.67.89/login")[10] == 1
    assert extract_features("http://example.com/login")[10] == 0


def test_at_credential_trick_is_authority_only_feat11():
    # '@' in the authority is the credential-hiding trick.
    assert extract_features("http://legit.com@evil.com")[11] == 1
    # '@' in path/query (e.g. an email address) must NOT flag.
    assert extract_features("http://good.com/path?email=a@b.com")[11] == 0
    assert extract_features("http://good.com")[11] == 0


def test_punycode_flag_feat20():
    assert extract_features("http://xn--pple-43d.com")[20] == 1
    assert extract_features("http://apple.com")[20] == 0


def test_non_ascii_host_flag_feat21():
    assert extract_features(f"http://{CYRILLIC_A}pple.com")[21] == 1
    assert extract_features("http://apple.com")[21] == 0


def test_suspicious_tld_flag_feat16():
    tld = next(t for t in SUSPICIOUS_TLDS if "." not in t)
    assert extract_features(f"http://weird-brandless-host.{tld}")[16] == 1
    assert extract_features("http://plain-example-site.com")[16] == 0


def test_brand_spoof_flag_feat8():
    # Look-alike of a real brand in the domain, but domain != brand -> spoof.
    assert extract_features("http://g00gle-account-login.com")[8] == 1
    # Real brand root (domain == brand) is NOT a spoof.
    assert extract_features("http://google.com")[8] == 0
    # Unrelated legit host is not a spoof.
    assert extract_features("http://example.com")[8] == 0
