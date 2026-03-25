from __future__ import annotations

import json
from typing import Any

import numpy as np

from bec_app.database import fetch_analyses
from bec_app.model_service import score_row as _score_row, behavior_model_source
from bec_app.phishing_model import phishing_probability


def score_row(features: dict[str, float]) -> tuple[float, float]:
    return _score_row(features)


def score_fused(
    features: dict[str, float],
    subject: str | None = None,
    body: str | None = None,
    phishing_weight: float = 0.42,
) -> tuple[float, float, float | None, float, str]:
    """
    Returns: combined_risk, behavior_risk, phishing_prob | None, raw_if_score, behavior_source
    """
    br, raw = score_row(features)
    src = behavior_model_source()
    sub = subject or ""
    bod = body or ""
    pp = phishing_probability(sub, bod)
    if pp is None:
        return br, br, None, raw, src
    w = float(np.clip(phishing_weight, 0.0, 0.95))
    combined = (1.0 - w) * br + w * pp
    return float(np.clip(combined, 0.0, 1.0)), br, pp, raw, src


def threat_level(risk: float, threshold: float) -> str:
    if risk >= threshold + 0.2:
        return "High"
    if risk >= threshold:
        return "Medium"
    return "Low"


def detect_issues(
    features: dict[str, float],
    risk: float,
    phishing_prob: float | None = None,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if features.get("location_distance_km", 0) > 800:
        issues.append(
            {
                "type": "Impossible travel",
                "detail": f"Login ~{features['location_distance_km']:.0f} km from typical location.",
                "severity": "High",
            }
        )
    if features.get("inbox_rule_changes", 0) >= 1:
        issues.append(
            {
                "type": "Suspicious inbox rule",
                "detail": f"{int(features['inbox_rule_changes'])} inbox rule change(s) in window.",
                "severity": "High" if features["inbox_rule_changes"] >= 2 else "Medium",
            }
        )
    if features.get("emails_per_hour", 0) > 40:
        issues.append(
            {
                "type": "Unusual sending volume",
                "detail": f"~{features['emails_per_hour']:.0f} emails/hour - possible auto-forward or blast.",
                "severity": "Medium",
            }
        )
    if features.get("login_time_delta_hours", 0) < 0.25 and features.get(
        "location_distance_km", 0
    ) > 500:
        issues.append(
            {
                "type": "Time/location mismatch",
                "detail": "Very short time delta with large geo jump.",
                "severity": "High",
            }
        )
    if features.get("recipient_count", 0) > 25:
        issues.append(
            {
                "type": "Mass recipients",
                "detail": f"{int(features['recipient_count'])} recipients - review for BEC staging.",
                "severity": "Medium",
            }
        )
    if phishing_prob is not None and phishing_prob >= 0.72:
        issues.append(
            {
                "type": "Phishing / BEC language (benchmark classifier)",
                "detail": f"Supervised head (Enron + phishing corpora): P(malicious)~{phishing_prob:.2f}.",
                "severity": "High" if phishing_prob >= 0.88 else "Medium",
            }
        )
    elif phishing_prob is not None and phishing_prob >= 0.55:
        issues.append(
            {
                "type": "Elevated phishing score",
                "detail": f"Text model score {phishing_prob:.2f} - review headers and sender policy.",
                "severity": "Low",
            }
        )
    if risk >= 0.7 and not issues:
        issues.append(
            {
                "type": "Anomaly (ML)",
                "detail": "Isolation Forest flagged this profile as anomalous.",
                "severity": "High",
            }
        )
    elif risk >= 0.45 and not issues:
        issues.append(
            {
                "type": "Elevated risk",
                "detail": "Composite behavior deviates from learned baseline.",
                "severity": "Low",
            }
        )
    return issues


def dashboard_series() -> dict[str, Any]:
    rows = fetch_analyses(500)
    times = []
    risks = []
    levels = {"Low": 0, "Medium": 0, "High": 0}
    loc_buckets: dict[str, int] = {}
    for r in rows:
        times.append(r["created_at"])
        risks.append(float(r["risk_score"]))
        lv = r["threat_level"]
        if lv in levels:
            levels[lv] += 1
        try:
            f = json.loads(r["features_json"])
            km = float(f.get("location_distance_km", 0))
            if km < 50:
                loc_buckets["< 50 km"] = loc_buckets.get("< 50 km", 0) + 1
            elif km < 500:
                loc_buckets["50–500 km"] = loc_buckets.get("50–500 km", 0) + 1
            elif km < 3000:
                loc_buckets["500–3000 km"] = loc_buckets.get("500–3000 km", 0) + 1
            else:
                loc_buckets["> 3000 km"] = loc_buckets.get("> 3000 km", 0) + 1
        except (json.JSONDecodeError, TypeError, KeyError):
            pass
    return {
        "times": times,
        "risks": risks,
        "levels": levels,
        "loc_buckets": loc_buckets,
        "total_analyses": len(rows),
    }
