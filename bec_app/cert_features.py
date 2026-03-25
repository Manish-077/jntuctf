"""Map CERT insider-threat logon traces into behavior feature vectors (7-D, same as app)."""
from __future__ import annotations

import numpy as np
import pandas as pd


def logon_df_to_training_matrix(df: pd.DataFrame, max_users: int = 400) -> np.ndarray:
    """One row per user: aggregate stats mapped to Isolation Forest feature space."""
    lower_map = {c.lower(): c for c in df.columns}
    need = ("date", "user", "pc", "activity")
    for k in need:
        if k not in lower_map:
            return np.zeros((0, 7))

    dcol = lower_map["date"]
    ucol = lower_map["user"]
    pcol = lower_map["pc"]
    acol = lower_map["activity"]

    df = df.copy()
    df["_ts"] = pd.to_datetime(df[dcol], errors="coerce")
    df = df.dropna(subset=["_ts"])
    if df.empty:
        return np.zeros((0, 7))

    rows: list[list[float]] = []
    users = df[ucol].dropna().unique()[:max_users]
    for u in users:
        udf = df[df[ucol] == u].sort_values("_ts")
        if len(udf) < 2:
            continue
        gaps = udf["_ts"].diff().dt.total_seconds().dropna() / 3600.0
        mean_gap = float(np.clip(gaps.mean(), 0.1, 168.0))
        nlogon = int(
            (udf[acol].astype(str).str.lower().str.contains("logon")).sum()
        )
        npc = udf[pcol].nunique()
        hour = udf["_ts"].dt.hour
        night_ratio = float(((hour < 6) | (hour > 22)).mean()) if len(udf) else 0.0
        weekend_ratio = float(udf["_ts"].dt.dayofweek.isin([5, 6]).mean())

        vec = [
            mean_gap,
            float(min(npc * 80.0, 12000.0)),
            float(min(nlogon * 2.0, 120.0)),
            1.0,
            float(1 if npc >= 4 else 0),
            float(3.0 + weekend_ratio * 2.0 + night_ratio),
            float(min(2.0 + night_ratio * 3.0, 5.0)),
        ]
        rows.append(vec)

    if not rows:
        return np.zeros((0, 7))
    return np.array(rows, dtype=np.float64)
