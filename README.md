# BEC Shield — Full-stack BEC detection platform

Streamlit UI + SQLite + Isolation Forest + rule engine + optional FastAPI. Built for demos and hackathon judging: multi-source ingest, visual pipeline, alerts, and analytics dashboard.

## Quick start (local)

```bash
cd bec-platform
pip install -r requirements.txt
streamlit run app.py
```

Open `http://localhost:8501`. Use the sidebar to move between Landing → Input → Processing → Results → Alerts → Dashboard → Admin.

**Sample CSV:** `data/sample_email_logs.csv`

## Optional REST API

```bash
cd bec-platform
uvicorn server:app --reload --port 8000
```

- `GET /health`
- `POST /analyze` — JSON body with `login_time_delta_hours`, `location_distance_km`, `emails_per_hour`, `recipient_count`, `inbox_rule_changes`, `subject_entropy`, `body_length_ratio`
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
- **ML:** `IsolationForest` + `StandardScaler`, trained on synthetic normal vs. anomalous feature mixes; rule layer maps to BEC-style issues.
- **Persistence:** SQLite (`analyses`, `alerts`, `users`, `settings`, `audit_log`).

Replace synthetic training data with your historical SIEM/IdP exports for production use.
