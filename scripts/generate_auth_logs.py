#!/usr/bin/env python3
"""Simulate Microsoft 365 / Gmail-style authentication + mail behavior logs (CSV)."""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, default=ROOT / "data" / "generated" / "sim_m365_gmail_auth.csv")
    p.add_argument("--rows", type=int, default=300)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()
    rng = np.random.default_rng(args.seed)
    n = args.rows
    # Benign majority + rare risky rows (simulated BEC staging / impossible travel)
    risky = rng.random(n) < 0.08
    login_delta = rng.gamma(2.0, 2.0, n)
    login_delta[risky] = rng.uniform(6, 96, risky.sum())
    dist_km = rng.exponential(200.0, n)
    dist_km[risky] = rng.uniform(2000, 11000, risky.sum())
    emails_h = rng.poisson(6.0, n).astype(float)
    emails_h[risky] = rng.poisson(45, risky.sum()).astype(float)
    recipients = rng.poisson(2.0, n).astype(float)
    recipients[risky] = rng.poisson(18, risky.sum()).astype(float)
    rules = rng.poisson(0.15, n).astype(float)
    rules[risky] = rng.poisson(2, risky.sum()).astype(float)
    subj_ent = rng.normal(3.4, 0.7, n)
    subj_ent[risky] = rng.uniform(5.0, 7.0, risky.sum())
    body_ratio = rng.exponential(0.85, n)
    body_ratio[risky] = rng.uniform(2.0, 4.5, risky.sum())

    df = pd.DataFrame(
        {
            "login_time_delta_hours": login_delta,
            "location_distance_km": dist_km,
            "emails_per_hour": emails_h,
            "recipient_count": recipients,
            "inbox_rule_changes": rules,
            "subject_entropy": subj_ent,
            "body_length_ratio": body_ratio,
            "risky_simulated_flag": risky.astype(int),
        }
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} rows -> {args.out}")


if __name__ == "__main__":
    main()
