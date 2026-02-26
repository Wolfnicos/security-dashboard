"""SQLite database layer for persisting security alerts."""

import sqlite3
from datetime import datetime
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent.parent.parent / "security.db"


def get_connection(db_path=None):
    db_path = db_path or DEFAULT_DB
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            ip          TEXT    NOT NULL,
            attack_type TEXT    NOT NULL,
            severity    TEXT    NOT NULL CHECK(severity IN ('low','medium','high','critical')),
            details     TEXT,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
    conn.commit()


def save_alerts(conn, alerts):
    """Persist a list of alert dicts into the database. Returns number of rows inserted."""
    rows = []
    for a in alerts:
        details = (
            f"{a['max_in_window']} failures in window | "
            f"{a['total_failures']} total | "
            f"users: {', '.join(a['users_targeted'][:10])}"
        )
        rows.append((
            a["window_start"].isoformat(),
            a["ip"],
            a["attack_type"],
            a["severity"],
            details,
        ))

    conn.executemany(
        "INSERT INTO alerts (timestamp, ip, attack_type, severity, details) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    return len(rows)


def get_alert_summary(conn):
    """Return summary stats from the alerts table."""
    cur = conn.execute("SELECT COUNT(*) as total FROM alerts")
    total = cur.fetchone()["total"]

    cur = conn.execute("""
        SELECT severity, COUNT(*) as cnt
        FROM alerts GROUP BY severity ORDER BY cnt DESC
    """)
    by_severity = {row["severity"]: row["cnt"] for row in cur.fetchall()}

    cur = conn.execute("""
        SELECT ip, COUNT(*) as cnt
        FROM alerts GROUP BY ip ORDER BY cnt DESC LIMIT 10
    """)
    top_ips = [(row["ip"], row["cnt"]) for row in cur.fetchall()]

    return {"total": total, "by_severity": by_severity, "top_ips": top_ips}
