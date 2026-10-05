"""
PhishGuard AI — Database Layer
Uses SQLite (dev) — swap DB_PATH to postgres:// for production.

Table: phishing_events
  id, type, content, result, risk_score, response_time_sec, timestamp
"""

import sqlite3
import datetime
import os
from contextlib import closing

DB_PATH = os.environ.get("PHISHGUARD_DB", "phishguard.db")


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist. Called once on startup."""
    with closing(_get_conn()) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS phishing_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                type            TEXT NOT NULL,          -- 'url'
                content         TEXT NOT NULL,          -- the scanned url string
                result          TEXT NOT NULL,          -- 'PHISHING' | 'SUSPICIOUS' | 'SAFE'
                risk_score      REAL NOT NULL,
                response_time   REAL DEFAULT 0,         -- seconds
                timestamp       TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON phishing_events(timestamp)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_result ON phishing_events(result)
        """)
        conn.commit()


def log_event(type_: str, content: str, result: str, risk_score: float, response_time: float = 0):
    """Insert one detection event into the database."""
    with closing(_get_conn()) as conn:
        conn.execute(
            """
            INSERT INTO phishing_events (type, content, result, risk_score, response_time, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                type_,
                content[:500],          # cap content length
                result,
                round(risk_score, 4),
                round(response_time, 4),
                datetime.datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()


def get_stats() -> dict:
    """
    Return KPI stats for the Power BI dashboard and the website dashboard page.
    KPIs:
      - total_scans
      - phishing_count, suspicious_count, safe_count
      - detection_rate  (phishing / total * 100)
      - false_positive_rate  (estimated: safe flagged — not tracked here, set 0)
      - avg_response_time_ms
      - url_scans
      - repeat_threat_rate  (domains seen > 1 time)
      - daily_breakdown (last 7 days)
    """
    with closing(_get_conn()) as conn:
        totals = conn.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN result = 'PHISHING'   THEN 1 ELSE 0 END) AS phishing,
                SUM(CASE WHEN result = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious,
                SUM(CASE WHEN result = 'SAFE'       THEN 1 ELSE 0 END) AS safe,
                SUM(CASE WHEN type   = 'url'        THEN 1 ELSE 0 END) AS url_scans,
                AVG(response_time) AS avg_response
            FROM phishing_events
        """).fetchone()

        daily = conn.execute("""
            SELECT
                DATE(timestamp) AS day,
                COUNT(*) AS total,
                SUM(CASE WHEN result = 'PHISHING' THEN 1 ELSE 0 END) AS phishing
            FROM phishing_events
            WHERE timestamp >= DATE('now', '-7 days')
            GROUP BY DATE(timestamp)
            ORDER BY day
        """).fetchall()

        top_threats = conn.execute("""
            SELECT content, COUNT(*) AS cnt
            FROM phishing_events
            WHERE result IN ('PHISHING', 'SUSPICIOUS') AND type = 'url'
            GROUP BY content
            ORDER BY cnt DESC
            LIMIT 10
        """).fetchall()

    total = totals["total"] or 1   # avoid division by zero
    phishing = totals["phishing"] or 0

    return {
        "total_scans": totals["total"] or 0,
        "phishing_count": phishing,
        "suspicious_count": totals["suspicious"] or 0,
        "safe_count": totals["safe"] or 0,
        "url_scans": totals["url_scans"] or 0,
        "detection_rate": round(phishing / total * 100, 2),
        "avg_response_time_ms": round((totals["avg_response"] or 0) * 1000, 1),
        "daily_breakdown": [dict(r) for r in daily],
        "top_threats": [dict(r) for r in top_threats],
    }


def get_recent_events(limit: int = 20) -> list:
    """Return the most recent detection events.

    `limit` is coerced to a sane non-negative int here as well as at the API
    edge — a negative value is SQLite's "no limit", which would dump the whole
    table, so clamp it defensively at the data layer too.
    """
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 20
    limit = max(0, limit)
    with closing(_get_conn()) as conn:
        rows = conn.execute(
            """
            SELECT id, type, content, result, risk_score, response_time, timestamp
            FROM phishing_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


# Auto-init on import
init_db()
