"""Scan history log — every scan, automatic or manual, gets written here
regardless of outcome. This is the audit trail the guardrail promise
depends on.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from detector.decision import ScanResult

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "scan_history.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,          -- "manual" | "auto"
    summary TEXT NOT NULL,         -- short human-readable label for the item
    label TEXT NOT NULL,
    score INTEGER NOT NULL,
    confidence TEXT NOT NULL,
    explanation TEXT NOT NULL,
    explanation_source TEXT NOT NULL,
    action TEXT NOT NULL,
    user_decision TEXT             -- null until confirmed/dismissed by a person
);
"""


@contextmanager
def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def log_scan(item: dict, result: ScanResult, source: str = "manual") -> int:
    summary = item.get("subject") or item.get("link") or item.get("sender_email") or "untitled scan"
    with _connect() as conn:
        cursor = conn.execute(
            """INSERT INTO scans
               (timestamp, source, summary, label, score, confidence, explanation, explanation_source, action)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                source,
                summary,
                result.label,
                result.score,
                result.confidence,
                result.explanation,
                result.explanation_source,
                result.action,
            ),
        )
        return cursor.lastrowid


def record_user_decision(scan_id: int, decision: str) -> None:
    with _connect() as conn:
        conn.execute("UPDATE scans SET user_decision = ? WHERE id = ?", (decision, scan_id))


def get_history(limit: int = 50) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


def summary_counts() -> dict:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT label, COUNT(*) as n FROM scans GROUP BY label"
        ).fetchall()
        counts = {"safe": 0, "suspicious": 0, "dangerous": 0}
        counts.update({row["label"]: row["n"] for row in rows})
        return counts
