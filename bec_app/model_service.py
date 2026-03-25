from __future__ import annotations

import functools

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from bec_app.config import ARTIFACTS_DIR, FEATURE_NAMES

_BEHAVIOR_PATH = ARTIFACTS_DIR / "behavior_if.joblib"


def _synthetic_normal(n: int = 400, seed: int = 42) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return np.column_stack(
        [
            rng.gamma(2.0, 2.0, n),
            rng.exponential(120.0, n),
            rng.poisson(6.0, n).astype(float),
            rng.poisson(2.0, n).astype(float),
            rng.poisson(0.3, n).astype(float),
            rng.normal(3.5, 0.8, n),
            rng.exponential(0.8, n),
        ]
    ).astype(np.float64)


def _synthetic_anomalies(n: int = 40, seed: int = 7) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return np.column_stack(
        [
            rng.uniform(48, 168, n),
            rng.uniform(2500, 12000, n),
            rng.poisson(80, n).astype(float),
            rng.poisson(35, n).astype(float),
            rng.poisson(4, n).astype(float),
            rng.uniform(5.5, 7.5, n),
            rng.uniform(2.5, 5.0, n),
        ]
    ).astype(np.float64)


@functools.lru_cache(maxsize=1)
def get_model_bundle():
    if _BEHAVIOR_PATH.exists():
        bundle = joblib.load(_BEHAVIOR_PATH)
        return bundle["scaler"], bundle["clf"], "benchmarks"
    X = np.vstack([_synthetic_normal(450), _synthetic_anomalies(50)])
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    clf = IsolationForest(
        n_estimators=200,
        contamination=0.08,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(Xs)
    return scaler, clf, "synthetic"


def clear_behavior_cache() -> None:
    get_model_bundle.cache_clear()


def behavior_model_source() -> str:
    return get_model_bundle()[2]


def vector_from_features(features: dict[str, float]) -> np.ndarray:
    row = []
    for k in FEATURE_NAMES:
        try:
            v = float(features.get(k, 0.0))
        except (TypeError, ValueError):
            v = 0.0
        if v != v or v in (float("inf"), float("-inf")):
            v = 0.0
        row.append(v)
    arr = np.array([row], dtype=np.float64)
    return np.nan_to_num(arr, nan=0.0, posinf=1e6, neginf=-1e6)


def score_row(features: dict[str, float]) -> tuple[float, float]:
    scaler, clf, _src = get_model_bundle()
    x = vector_from_features(features)
    xs = scaler.transform(x)
    raw = float(-clf.score_samples(xs)[0])
    decision = float(clf.decision_function(xs)[0])
    risk = float(np.clip((raw - 0.35) / 0.45, 0.0, 1.0))
    if decision < -0.02:
        risk = min(1.0, risk + 0.15)
    return risk, raw
