"""Loaders for hackathon benchmark CSVs (Kaggle Enron, phishing, CERT insider threat)."""
from __future__ import annotations

from pathlib import Path

import pandas as pd


def _first_col(df: pd.DataFrame, candidates: list[str]) -> str | None:
    lower = {c.lower().strip(): c for c in df.columns}
    for name in candidates:
        if name.lower() in lower:
            return lower[name.lower()]
    return None


def load_enron_style_csv(path: str | Path) -> pd.DataFrame:
    """
    Kaggle 'Enron Email Dataset' style: subject/body/message columns.
    Returns columns: subject, body (str).
    """
    path = Path(path)
    df = pd.read_csv(path, encoding="utf-8", on_bad_lines="skip", low_memory=False)
    if df.empty:
        return pd.DataFrame({"subject": [], "body": []})
    c_subj = _first_col(
        df,
        ["subject", "Subject", "SUBJECT", "email_subject", "title"],
    )
    c_body = _first_col(
        df,
        ["body", "Body", "message", "Message", "content", "text", "email_body", "mail_body"],
    )
    c_one = _first_col(df, ["mail", "email", "Message_body"])
    subj_series = (
        df[c_subj].fillna("").astype(str) if c_subj else pd.Series([""] * len(df))
    )
    if c_body:
        body_series = df[c_body].fillna("").astype(str)
    elif c_one:
        full = df[c_one].fillna("").astype(str)
        body_series = full
        if not c_subj:
            subj_series = full.str.slice(0, 120)
    else:
        body_series = pd.Series([""] * len(df))
    out = pd.DataFrame({"subject": subj_series.values, "body": body_series.values})
    return out


def load_phishing_labeled_csv(path: str | Path) -> pd.DataFrame:
    """
    Phishing vs legitimate: expects label ∈ {0,1} or {phishing,legitimate} or Email Type.
    Returns columns: text, label (int 0 legit, 1 phish).
    """
    path = Path(path)
    df = pd.read_csv(path, encoding="utf-8", on_bad_lines="skip", low_memory=False)
    if df.empty:
        return pd.DataFrame({"text": [], "label": []})

    c_text = _first_col(
        df,
        ["text", "Email Text", "email_text", "message", "Message", "combined", "body"],
    )
    c_sub = _first_col(df, ["subject", "Subject"])
    c_body = _first_col(df, ["body", "Body", "message_body"])

    if c_text:
        text_series = df[c_text].fillna("").astype(str)
    elif c_sub and c_body:
        text_series = df[c_sub].fillna("").astype(str) + " " + df[c_body].fillna(
            ""
        ).astype(str)
    else:
        raise ValueError(
            "Phishing CSV needs a text column (text/message/body) or subject+body."
        )

    c_lab = _first_col(
        df,
        ["label", "Label", "class", "Category", "Email Type", "type", "is_phishing", "phishing"],
    )
    if not c_lab:
        raise ValueError("Phishing CSV needs a label column (label / Email Type / class).")

    raw = df[c_lab]
    labels: list[int] = []
    for v in raw:
        if pd.isna(v):
            labels.append(0)
            continue
        s = str(v).strip().lower()
        if s in ("1", "true", "phishing", "phish", "spam", "yes", "malicious"):
            labels.append(1)
        elif s in ("0", "false", "legitimate", "ham", "safe", "no", "normal", "benign"):
            labels.append(0)
        else:
            try:
                labels.append(1 if float(s) >= 0.5 else 0)
            except ValueError:
                labels.append(1 if "phish" in s else 0)

    return pd.DataFrame({"text": text_series.values, "label": labels})


def load_cert_logon_csv(path: str | Path) -> pd.DataFrame:
    """
    CERT Insider Threat Dataset (e.g. r4.2 / r6.2) logon.csv:
    id, date, user, pc, activity — tolerate renames.
    """
    path = Path(path)
    df = pd.read_csv(path, encoding="utf-8", on_bad_lines="skip", low_memory=False)
    if df.empty:
        return df
    ren = {}
    for std, alts in [
        ("id", ["id", "Index"]),
        ("date", ["date", "datetime", "time"]),
        ("user", ["user", "User"]),
        ("pc", ["pc", "machine", "computer", "hostname"]),
        ("activity", ["activity", "action", "type"]),
    ]:
        found = _first_col(df, [std] + alts)
        if found and found != std:
            ren[found] = std
    return df.rename(columns=ren)
