"""
Locks the D1 local blocklist loader that replaced the dead live PhishTank POST:
it must load a large snapshot at import, match an entry it contains exactly, and
not match arbitrary URLs. This guards against a silent path/format regression
that would make check_blocklist() always return False again.
"""
import main


def test_blocklist_loaded_and_large():
    assert isinstance(main._PHISH_BLOCKLIST, frozenset)
    assert len(main._PHISH_BLOCKLIST) > 1000     # ~75k live entries


def test_known_entry_matches_and_unknown_does_not():
    sample = next(iter(main._PHISH_BLOCKLIST))
    assert main.check_blocklist(sample) is True
    # trailing-slash tolerance path
    assert main.check_blocklist(sample.rstrip("/")) is True
    # something that cannot be in any feed
    assert main.check_blocklist("https://not-listed-zzz-9931-unique.example/") is False
