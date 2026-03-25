# BEC Shield — Full-stack BEC detection platform

Streamlit UI + SQLite + **dual ML stack** (Isolation Forest on behavior + TF‑IDF/logistic regression on email text) + rule engine + optional FastAPI. Benchmark-ready for **Enron**, **phishing**, **CERT insider threat**, and **simulated M365/Gmail** logs (see `data/benchmarks/README.md`).

## Quick start (local)

```bash
cd bec-platform
pip install -r requirements.txt
streamlit run app.py
```

Open `http://localhost:8501`. Sidebar: Landing → Input → **Datasets / benchmarks** (train models, generate auth CSV) → Processing → Results → Alerts → Dashboard → Admin.

Train benchmark models (writes `data/artifacts/*.joblib`):

```bash
python scripts/train_benchmark_models.py
python scripts/generate_auth_logs.py --rows 500
```

**Sample CSV:** `data/sample_email_logs.csv`

## Optional REST API

```bash
cd bec-platform
uvicorn server:app --reload --port 8000
```

- `GET /health`
- `POST /analyze` — JSON with the seven numeric features plus optional `subject` / `body` for phishing-head fusion
- `GET /alerts`

## Docker (UI only)

```bash
docker build -t bec-shield .
docker run -p 8501:8501 -v bec_data:/app/data bec-shield
```

## Docker Compose (UI + API)

```bash
docker compose up --build
```

- UI: `http://localhost:8501`
- API: `http://localhost:8000/docs`

SQLite database is stored under `data/bec_platform.db` (persist the `data` directory in production).

## Deploy hints

- **Streamlit Community Cloud:** push this folder to GitHub, set main file to `app.py`, Python 3.11.
- **Railway / Render / Fly.io:** use the `Dockerfile` or run `streamlit run app.py` with `PORT` from the platform and `--server.address=0.0.0.0`.

## Architecture

- **Frontend:** Streamlit (`app.py`) with custom CSS and Plotly charts.
- **Backend:** Python modules in `bec_app/` (database, features, ML).
- **ML:** (1) Behavior: `IsolationForest` + `StandardScaler` — default synthetic mix, or retrained on CERT + simulated auth CSV; (2) Text: `TfidfVectorizer` + `LogisticRegression` on Enron-style ham + phishing labels (toy CSVs included; swap for Kaggle dumps).
- **Persistence:** SQLite (`analyses`, `alerts`, `users`, `settings`, `audit_log`).

Replace synthetic training data with your historical SIEM/IdP exports for production use.
