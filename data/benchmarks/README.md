# Hackathon benchmark data

## Bundled toy sets (always safe to ship)

- **`enron_toy_normal.csv`** — short synthetic corporate mail in the spirit of the [Enron Email Dataset](https://www.kaggle.com/datasets/wcukierski/enron-email-dataset); replace with your Kaggle export for real experiments.
- **`phishing_toy_labeled.csv`** — synthetic ham/phish lines mimicking typical UCI/Kaggle phishing tasks; swap for a full [phishing email dataset](https://www.kaggle.com/datasets) when available.

## External datasets (place under `data/external/`)

| Source | Typical files | Use |
|--------|----------------|-----|
| **Enron (Kaggle)** | Single CSV or mail dump | Negative (legitimate) training text for the phishing classifier |
| **Phishing (Kaggle/UCI)** | `text` + `label` / `Email Type` | Positive/negative supervised head |
| **CERT Insider Threat** e.g. r4.2/r6.2 | `logon.csv` | User-level aggregates → behavior Isolation Forest |
| **Simulated auth** | `scripts/generate_auth_logs.py` | M365/Gmail-style structured features |

## Train models

From repo root:

```bash
python scripts/train_benchmark_models.py
```

With your downloads:

```bash
python scripts/train_benchmark_models.py ^
  --enron data/external/enron_emails.csv ^
  --phishing data/external/phishing_emails.csv ^
  --cert-logon data/external/logon.csv ^
  --sim-auth data/generated/sim_m365_gmail_auth.csv
```

Outputs: `data/artifacts/behavior_if.joblib`, `data/artifacts/phishing_pipeline.joblib`

Restart Streamlit after training (or use **Datasets & benchmarks** → *Reload model caches*).

## Generate simulated auth logs

```bash
python scripts/generate_auth_logs.py --rows 500
```
