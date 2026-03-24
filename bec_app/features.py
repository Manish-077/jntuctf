from __future__ import annotations

import math
from collections import Counter
from datetime import datetime
from typing import Any

import pandas as pd


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text.lower())
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)


def manual_to_features(
    sender: str,
    receiver: str,
    subject: str,
    body: str,
    login_lat: float,
    login_lon: float,
    baseline_lat: float,
    baseline_lon: float,
    login_time: datetime,
    last_login_time: datetime | None,
    recipient_count: int,
    inbox_rule_changes: int,
) -> dict[str, float]:
    delta_h = 0.0
    if last_login_time:
        delta_h = abs((login_time - last_login_time).total_seconds()) / 3600.0
    dist = _haversine_km(login_lat, login_lon, baseline_lat, baseline_lon)
    combined = f"{subject}\n{body}"
    return {
        "login_time_delta_hours": float(min(delta_h, 168.0)),
        "location_distance_km": float(min(dist, 20000.0)),
        "emails_per_hour": 12.0,
        "recipient_count": float(max(0, recipient_count)),
        "inbox_rule_changes": float(max(0, inbox_rule_changes)),
        "subject_entropy": _entropy(subject),
        "body_length_ratio": min(len(body) / 500.0, 5.0) if body else 0.0,
    }


def csv_row_to_features(row: pd.Series, col_map: dict[str, str]) -> dict[str, float] | None:
    def g(name: str, default: float = 0.0) -> float:
        key = col_map.get(name)
        if not key or key not in row.index:
            return default
        v = row[key]
        if pd.isna(v):
            return default
        try:
            return float(v)
        except (TypeError, ValueError):
            return default

    def gs(name: str, default: str = "") -> str:
        key = col_map.get(name)
        if not key or key not in row.index:
            return default
        v = row[key]
        if pd.isna(v):
            return default
        return str(v)

    subj = gs("subject")
    body = gs("body")
    combined_len = len(subj) + len(body)
    return {
        "login_time_delta_hours": g("login_time_delta_hours", 2.0),
        "location_distance_km": g("location_distance_km", 50.0),
        "emails_per_hour": g("emails_per_hour", 5.0),
        "recipient_count": g("recipient_count", 1.0),
        "inbox_rule_changes": g("inbox_rule_changes", 0.0),
        "subject_entropy": _entropy(subj) if subj else 2.0,
        "body_length_ratio": min(combined_len / 500.0, 5.0),
    }


def suggest_column_map(columns: list[str]) -> dict[str, str]:
    lower = {c.lower().strip(): c for c in columns}
    aliases = {
        "login_time_delta_hours": [
            "login_time_delta_hours",
            "time_delta",
            "hours_since_last",
        ],
        "location_distance_km": ["location_distance_km", "distance_km", "geo_distance"],
        "emails_per_hour": ["emails_per_hour", "email_rate"],
        "recipient_count": ["recipient_count", "recipients", "num_recipients"],
        "inbox_rule_changes": ["inbox_rule_changes", "rule_changes"],
        "subject": ["subject", "email_subject"],
        "body": ["body", "content", "email_body"],
    }
    out: dict[str, str] = {}
    for canon, names in aliases.items():
        for n in names:
            if n in lower:
                out[canon] = lower[n]
                break
    return out


def _safe_float(val: Any, default: float) -> float:
    try:
        x = float(val)
    except (TypeError, ValueError):
        return default
    if x != x or x in (float("inf"), float("-inf")):
        return default
    return x


def api_payload_to_features(payload: dict[str, Any]) -> dict[str, float]:
    return {
        "login_time_delta_hours": _safe_float(payload.get("login_time_delta_hours"), 1.5),
        "location_distance_km": _safe_float(payload.get("location_distance_km"), 25.0),
        "emails_per_hour": _safe_float(payload.get("emails_per_hour"), 8.0),
        "recipient_count": _safe_float(payload.get("recipient_count"), 2.0),
        "inbox_rule_changes": _safe_float(payload.get("inbox_rule_changes"), 0.0),
        "subject_entropy": _safe_float(payload.get("subject_entropy"), 3.2),
        "body_length_ratio": _safe_float(payload.get("body_length_ratio"), 1.0),
    }
