"""TF-IDF + logistic regression trained on phishing vs legitimate (Enron / UCI / Kaggle-style CSV)."""
from __future__ import annotations

import functools

import joblib
import numpy as np

from bec_app.config import ARTIFACTS_DIR

_PIPELINE_PATH = ARTIFACTS_DIR / "phishing_pipeline.joblib"


@functools.lru_cache(maxsize=1)
def get_phishing_pipeline():
    if _PIPELINE_PATH.exists():
        return joblib.load(_PIPELINE_PATH)
    return None


def clear_phishing_cache() -> None:
    get_phishing_pipeline.cache_clear()


def _positive_class_index(pipe) -> int:
    lr = pipe.named_steps.get("lr") if hasattr(pipe, "named_steps") else None
    est = lr if lr is not None else pipe
    classes = np.asarray(est.classes_)
    idxs = np.where(classes == 1)[0]
    if len(idxs):
        return int(idxs[0])
    if len(classes) >= 2:
        return 1
    return 0


def phishing_probability(subject: str, body: str) -> float | None:
    pipe = get_phishing_pipeline()
    if pipe is None:
        return None
    text = f"{subject or ''}\n{body or ''}".strip()
    if len(text) < 3:
        return None
    proba = pipe.predict_proba([text])[0]
    idx = _positive_class_index(pipe)
    return float(proba[idx])
