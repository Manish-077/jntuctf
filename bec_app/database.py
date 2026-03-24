import json
import math
import sqlite3
import uuid
from datetime import datetime
from typing import Any

from bec_app.config import DB_PATH, DATA_DIR


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}


def _sanitize_features_for_json(features: dict[str, float]) -> dict[str, float]:
    out: dict[str, float] = {}
    for k, v in features.items():
        if isinstance(v, float):
            if math.isnan(v) or math.isinf(v):
                out[k] = 0.0
            else:
                out[k] = v
        else:
            try:
                out[k] = float(v)
            except (TypeError, ValueError):
                out[k] = 0.0
    return out


def _conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    c = _conn()
    try:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                input_type TEXT NOT NULL,
                risk_score REAL NOT NULL,
                threat_level TEXT NOT NULL,
                issues_json TEXT NOT NULL,
                features_json TEXT NOT NULL,
                raw_summary TEXT
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT,
                analysis_id TEXT,
                status TEXT DEFAULT 'open'
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT
            );
            """
        )
        c.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('risk_threshold', '0.55')"
        )
        c.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('org_name', 'BEC Shield')"
        )
        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            now = datetime.utcnow().isoformat()
            c.execute(
                "INSERT INTO users (id, email, role, created_at) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), "admin@demo.security", "admin", now),
            )
            c.execute(
                "INSERT INTO users (id, email, role, created_at) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), "analyst@demo.security", "analyst", now),
            )
        c.commit()
    finally:
        c.close()


def get_setting(key: str, default: str = "") -> str:
    c = _conn()
    try:
        row = c.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default
    finally:
        c.close()


def set_setting(key: str, value: str) -> None:
    c = _conn()
    try:
        c.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        c.commit()
    finally:
        c.close()


def insert_analysis(
    input_type: str,
    risk_score: float,
    threat_level: str,
    issues: list[dict],
    features: dict[str, float],
    raw_summary: str | None = None,
) -> str:
    aid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    safe_features = _sanitize_features_for_json(features)
    c = _conn()
    try:
        c.execute(
            """INSERT INTO analyses (id, created_at, input_type, risk_score, threat_level, issues_json, features_json, raw_summary)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                aid,
                now,
                input_type,
                risk_score,
                threat_level,
                json.dumps(issues),
                json.dumps(safe_features),
                raw_summary,
            ),
        )
        c.commit()
    finally:
        c.close()
    return aid


def insert_alert(
    severity: str,
    title: str,
    detail: str | None,
    analysis_id: str | None = None,
) -> str:
    lid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    c = _conn()
    try:
        c.execute(
            """INSERT INTO alerts (id, created_at, severity, title, detail, analysis_id, status)
               VALUES (?, ?, ?, ?, ?, ?, 'open')""",
            (lid, now, severity, title, detail, analysis_id),
        )
        c.commit()
    finally:
        c.close()
    return lid


def update_alert_status(alert_id: str, status: str) -> None:
    c = _conn()
    try:
        c.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        c.commit()
    finally:
        c.close()


def log_audit(action: str, detail: str | None = None) -> None:
    c = _conn()
    try:
        c.execute(
            "INSERT INTO audit_log (id, created_at, action, detail) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), datetime.utcnow().isoformat(), action, detail),
        )
        c.commit()
    finally:
        c.close()


def fetch_analyses(limit: int = 200) -> list[sqlite3.Row]:
    c = _conn()
    try:
        return list(
            c.execute(
                "SELECT * FROM analyses ORDER BY datetime(created_at) DESC LIMIT ?",
                (limit,),
            )
        )
    finally:
        c.close()


def fetch_alerts(limit: int = 100) -> list[sqlite3.Row]:
    c = _conn()
    try:
        return list(
            c.execute(
                "SELECT * FROM alerts ORDER BY datetime(created_at) DESC LIMIT ?",
                (limit,),
            )
        )
    finally:
        c.close()


def fetch_users() -> list[sqlite3.Row]:
    c = _conn()
    try:
        return list(c.execute("SELECT * FROM users ORDER BY created_at"))
    finally:
        c.close()


def fetch_audit(limit: int = 100) -> list[sqlite3.Row]:
    c = _conn()
    try:
        return list(
            c.execute(
                "SELECT * FROM audit_log ORDER BY datetime(created_at) DESC LIMIT ?",
                (limit,),
            )
        )
    finally:
        c.close()


def add_user(email: str, role: str = "analyst") -> str:
    uid = str(uuid.uuid4())
    c = _conn()
    try:
        c.execute(
            "INSERT INTO users (id, email, role, created_at) VALUES (?, ?, ?, ?)",
            (uid, email.strip(), role, datetime.utcnow().isoformat()),
        )
        c.commit()
        return uid
    except sqlite3.IntegrityError as e:
        c.rollback()
        raise ValueError("User email already exists") from e
    finally:
        c.close()
