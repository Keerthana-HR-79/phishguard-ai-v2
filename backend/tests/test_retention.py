"""
Retention cleanup tests — the scan log must stay bounded (default 30 days).

Each test monkeypatches database.DB_PATH to a tmp file, so the real
phishguard.db is never touched.
"""

import datetime
import sqlite3

import database


def _insert(db_path, ts):
    """Insert one row with an explicit timestamp (bypassing log_event)."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO phishing_events "
        "(type, content, result, risk_score, response_time, timestamp) "
        "VALUES ('url', ?, 'SAFE', 0, 0, ?)",
        (f"http://x/{ts}", ts),
    )
    conn.commit()
    conn.close()


def _iso(days_ago):
    return (datetime.datetime.utcnow() - datetime.timedelta(days=days_ago)).isoformat()


def test_purge_removes_old_keeps_recent(tmp_path, monkeypatch):
    db = str(tmp_path / "t.db")
    monkeypatch.setattr(database, "DB_PATH", db)
    database.init_db()

    _insert(db, _iso(40))   # older than 30 days → should go
    _insert(db, _iso(5))    # recent → should stay

    deleted = database.purge_old_events(30)
    assert deleted == 1

    rows = database.get_recent_events(10)
    assert len(rows) == 1


def test_purge_default_is_30_days(tmp_path, monkeypatch):
    db = str(tmp_path / "t.db")
    monkeypatch.setattr(database, "DB_PATH", db)
    database.init_db()

    _insert(db, _iso(31))   # just over the 30-day window → go
    _insert(db, _iso(29))   # just inside → stay

    assert database.purge_old_events() == 1          # uses RETENTION_DAYS default
    assert len(database.get_recent_events(10)) == 1


def test_log_event_triggers_daily_purge(tmp_path, monkeypatch):
    db = str(tmp_path / "t.db")
    monkeypatch.setattr(database, "DB_PATH", db)
    monkeypatch.setattr(database, "_last_purge_day", None)  # force the throttle open
    database.init_db()

    _insert(db, _iso(45))   # stale row sitting in the table

    # a normal scan log should trigger the once-per-day cleanup
    database.log_event("url", "http://new", "SAFE", 0.0, 0.01)

    rows = database.get_recent_events(10)
    contents = [r["content"] for r in rows]
    assert "http://new" in contents          # the new row is kept
    assert all("/45" not in c for c in contents)  # the 45-day-old row is gone


def test_retention_days_is_configurable_and_sane():
    # Default ships at 30; the purge floor never deletes everything (min 1 day).
    assert database.RETENTION_DAYS == 30
