"""FastAPI backend for BEC platform (optional companion to Streamlit UI)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from bec_app.database import (
    fetch_alerts,
    get_setting,
    init_db,
    insert_alert,
    insert_analysis,
)
from bec_app.features import api_payload_to_features
from bec_app.ml_engine import detect_issues, score_row, threat_level

init_db()

app = FastAPI(title="BEC Detection API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeBody(BaseModel):
    login_time_delta_hours: float = Field(default=2.0)
    location_distance_km: float = Field(default=80.0)
    emails_per_hour: float = Field(default=10.0)
    recipient_count: float = Field(default=3.0)
    inbox_rule_changes: float = Field(default=0.0)
    subject_entropy: float = Field(default=3.5)
    body_length_ratio: float = Field(default=1.2)
    input_type: str = "api"


@app.get("/health")
def health():
    return {"status": "ok", "service": "bec-detection-api"}


@app.post("/analyze")
def analyze(body: AnalyzeBody):
    threshold = float(get_setting("risk_threshold", "0.55"))
    d = body.model_dump() if hasattr(body, "model_dump") else body.dict()
    d.pop("input_type", None)
    feats = api_payload_to_features(d)
    risk, _raw = score_row(feats)
    level = threat_level(risk, threshold)
    issues = detect_issues(feats, risk)
    aid = insert_analysis(
        "api",
        risk,
        level,
        issues,
        feats,
        json.dumps(body.model_dump()),
    )
    if level in ("Medium", "High"):
        insert_alert(
            "High" if level == "High" else "Medium",
            f"BEC risk {level}",
            f"Analysis {aid[:8]}… score {risk:.2f}",
            aid,
        )
    return {
        "analysis_id": aid,
        "risk_score": risk,
        "risk_percent": round(risk * 100, 1),
        "threat_level": level,
        "issues": issues,
        "features": feats,
    }


@app.get("/alerts")
def alerts():
    rows = fetch_alerts(80)
    return [
        {
            "id": r["id"],
            "created_at": r["created_at"],
            "severity": r["severity"],
            "title": r["title"],
            "detail": r["detail"],
            "status": r["status"],
        }
        for r in rows
    ]
