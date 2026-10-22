"""SQLite storage for past scans."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    score       INTEGER NOT NULL,
    level       TEXT NOT NULL,
    report_json TEXT NOT NULL,
    scanned_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans (scanned_at DESC);
"""


def _db_path() -> str:
    return os.getenv("DATABASE_PATH", "history.db")


@contextmanager
def _connect():
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(SCHEMA)


def save_scan(report) -> int:
    """Store a RiskReport and return its new id."""
    data = report.to_dict()
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans (url, hostname, score, level, report_json, scanned_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (data["url"], data["hostname"], data["score"], data["level"],
             json.dumps(data), data["scanned_at"]),
        )
        return cur.lastrowid


def get_history(limit: int = 50) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, url, hostname, score, level, scanned_at "
            "FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    out = dict(row)
    out["report"] = json.loads(out.pop("report_json"))
    return out


def clear_history() -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM scans")