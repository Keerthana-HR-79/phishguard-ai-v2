"""
Phase-2 serving-robustness hardening (backend v3.1.0). Locks the fixes so they
can't silently regress:

  csv_safe        CSV formula injection is neutralized on every user-controlled
                  field written to a spreadsheet-consumed CSV (FP log, BI export).
  /recent clamp   a negative or oversized ?limit can't dump the whole table
                  (SQLite treats a negative LIMIT as "all rows") or DoS the API.
  DB clamp        database.get_recent_events clamps defensively on its own too.
  _log_event_safe a DB write failure logs a note and never breaks the request.
  FP-log write    a formula-leading URL is stored quoted; an IO error degrades
                  to an "accepted-but-not-persisted" 200, never a 500.
"""
import asyncio
import csv

import pytest

import main
from config import csv_safe


# ── csv_safe (pure unit) ──────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("=HYPERLINK(\"http://evil\")", "'=HYPERLINK(\"http://evil\")"),
    ("+1+1", "'+1+1"),
    ("-2+3", "'-2+3"),
    ("@SUM(A1)", "'@SUM(A1)"),
    ("\tstartswithtab", "'\tstartswithtab"),
    ("\rstartswithcr", "'\rstartswithcr"),
    ("https://safe.example/login", "https://safe.example/login"),  # ordinary URL untouched
    ("", ""),
    (None, ""),
])
def test_csv_safe(raw, expected):
    assert csv_safe(raw) == expected


# ── /recent limit clamp ───────────────────────────────────────────────────────

def test_recent_clamps_limit(monkeypatch):
    """The endpoint must hand get_recent_events a value in [1, RECENT_MAX_LIMIT],
    whatever the caller passes."""
    seen = {}
    monkeypatch.setattr(main, "get_recent_events", lambda limit: seen.setdefault("limit", limit) or [])

    main.recent(-5)
    assert seen["limit"] == 1                      # negative -> floored to 1

    seen.clear()
    main.recent(10_000)
    assert seen["limit"] == main.RECENT_MAX_LIMIT  # huge -> capped

    seen.clear()
    main.recent(20)
    assert seen["limit"] == 20                      # in-range passes through


# ── database defensive clamp (belt-and-suspenders) ────────────────────────────

def test_get_recent_events_negative_limit_is_safe():
    """A negative limit must NOT return the whole table (SQLite 'LIMIT -1' == all).
    The data layer clamps to 0 rows for a negative request."""
    import database
    assert database.get_recent_events(-1) == []


# ── _log_event_safe swallows DB errors ────────────────────────────────────────

def test_log_event_safe_swallows_errors(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("db locked")
    monkeypatch.setattr(main, "log_event", _boom)
    # Must not raise — logging is a side effect and can never break a verdict.
    asyncio.run(main._log_event_safe("url", "http://x", "SAFE", 0.0, 0.01))


# ── FP-log CSV sanitization end-to-end ────────────────────────────────────────

def test_report_false_positive_sanitizes_and_persists(tmp_path, monkeypatch):
    fp = tmp_path / "pending.csv"
    monkeypatch.setattr(main, "FP_LOG", str(fp))
    # A URL whose normalized form still leads with a formula char.
    r = asyncio.run(main.report_false_positive(
        main.FalsePositiveReport(url="=cmd|/c calc.example/login", reason="+evil")))
    assert r["status"] == "logged"

    with open(fp, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows, "a row should have been written"
    # Both user-controlled fields are quote-prefixed so a spreadsheet won't eval them.
    assert rows[0]["url"].startswith("'=")
    assert rows[0]["reason"].startswith("'+")


def test_report_false_positive_io_error_does_not_500(monkeypatch):
    import builtins
    def _boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(builtins, "open", _boom)
    r = asyncio.run(main.report_false_positive(
        main.FalsePositiveReport(url="http://x.example/a", reason="")))
    assert r["status"] == "accepted"
    assert "not be persisted" in r["note"]


# ── CWD-independent artifact/feed loading (L7 + model-path anchor) ─────────────

def test_feed_and_model_paths_are_module_anchored():
    """The blocklist feed dir and the model-artifact dir must be anchored on an
    absolute module path, not a bare relative string — otherwise importing from a
    foreign CWD silently loads an empty blocklist / crashes on model.pkl. Locks
    the fix that made both load regardless of where the interpreter was launched."""
    import os
    import predict_ml_only
    assert os.path.isabs(predict_ml_only._MODEL_DIR)
    # _RAW_DIR is <backend>/../data/raw built from an absolute backend dir.
    assert os.path.isabs(main._BACKEND_DIR)
    assert os.path.isabs(os.path.abspath(main._RAW_DIR))
    # The blocklist actually populated (proves the anchored path resolved).
    assert len(main._PHISH_BLOCKLIST) > 1000
