#!/usr/bin/env python3
"""
Train behavior IsolationForest + phishing TF-IDF/LR using hackathon datasets.

Optional paths (download from Kaggle / CERT and place under data/external/):
  - Enron-style CSV (corporate ham baseline)
  - Phishing labeled CSV
  - CERT logon.csv
  - Simulated auth CSV (from scripts/generate_auth_logs.py)

Without paths, uses toy CSVs under data/benchmarks/ so the pipeline always runs.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bec_app.cert_features import logon_df_to_training_matrix
from bec_app.config import ARTIFACTS_DIR, DATA_DIR, FEATURE_NAMES
from bec_app.datasets.loaders import (
    load_cert_logon_csv,
    load_enron_style_csv,
    load_phishing_labeled_csv,
)
from bec_app.model_service import _synthetic_anomalies, _synthetic_normal


def _synth_stack():
    return np.vstack([_synthetic_normal(400), _synthetic_anomalies(45)])


def main() -> None:
    parser = argparse.ArgumentParser(description="Train BEC Shield benchmark models")
    parser.add_argument("--enron", type=Path, help="Enron / corporate email CSV (Kaggle export)")
    parser.add_argument("--phishing", type=Path, help="Phishing labeled CSV (Kaggle / UCI style)")
    parser.add_argument("--cert-logon", type=Path, help="CERT insider threat logon.csv")
    parser.add_argument("--sim-auth", type=Path, help="Simulated M365/Gmail auth CSV")
    args = parser.parse_args()

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    bench = DATA_DIR / "benchmarks"
    enron_p = args.enron if args.enron and args.enron.exists() else bench / "enron_toy_normal.csv"
    phish_p = args.phishing if args.phishing and args.phishing.exists() else bench / "phishing_toy_labeled.csv"

    Xparts = [_synth_stack()]
    if args.cert_logon and args.cert_logon.exists():
        cdf = load_cert_logon_csv(args.cert_logon)
        Xm = logon_df_to_training_matrix(cdf)
        if len(Xm):
            Xparts.append(Xm)
            print(f"CERT: added {len(Xm)} user aggregate rows")
    if args.sim_auth and args.sim_auth.exists():
        adf = pd.read_csv(args.sim_auth)
        if all(c in adf.columns for c in FEATURE_NAMES):
            sim_mat = adf[list(FEATURE_NAMES)].astype(float).values
            Xparts.append(sim_mat)
            print(f"Sim auth: added {len(sim_mat)} rows")
        else:
            print("Sim auth: CSV must include all columns:", ", ".join(FEATURE_NAMES))

    X = np.vstack(Xparts)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    iso = IsolationForest(
        n_estimators=220,
        contamination=max(0.04, min(0.12, 50 / (len(X) + 1))),
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(Xs)
    behavior_path = ARTIFACTS_DIR / "behavior_if.joblib"
    joblib.dump({"scaler": scaler, "clf": iso, "feature_names": list(FEATURE_NAMES)}, behavior_path)
    print(f"Wrote behavior IF -> {behavior_path} (rows={len(X)})")

    # Phishing + Enron ham
    en = load_enron_style_csv(enron_p)
    ph = load_phishing_labeled_csv(phish_p)
    texts: list[str] = []
    labels: list[int] = []
    max_ham = min(len(en), 8000)
    for _, r in en.head(max_ham).iterrows():
        t = f"{r['subject']}\n{r['body']}".strip()
        if len(t) > 10:
            texts.append(t[:20000])
            labels.append(0)
    for _, r in ph.iterrows():
        t = str(r["text"]).strip()
        if len(t) > 5:
            texts.append(t[:20000])
            labels.append(int(r["label"]))

    if len(set(labels)) < 2 or len(texts) < 8:
        print("Not enough labeled text rows; skipping phishing pipeline")
        return

    n = len(texts)
    min_df = 1 if n < 80 else 2
    max_feat = min(6000, max(256, n * 4))
    pipe = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    max_features=max_feat,
                    min_df=min_df,
                    ngram_range=(1, 2),
                    sublinear_tf=True,
                ),
            ),
            (
                "lr",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=300,
                    random_state=42,
                ),
            ),
        ]
    )
    pipe.fit(texts, labels)
    phish_path = ARTIFACTS_DIR / "phishing_pipeline.joblib"
    joblib.dump(pipe, phish_path)
    print(f"Wrote phishing classifier -> {phish_path} (docs={len(texts)})")


if __name__ == "__main__":
    main()
