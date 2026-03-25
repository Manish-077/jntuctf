from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
ARTIFACTS_DIR = DATA_DIR / "artifacts"
DB_PATH = DATA_DIR / "bec_platform.db"

ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

FEATURE_NAMES = [
    "login_time_delta_hours",
    "location_distance_km",
    "emails_per_hour",
    "recipient_count",
    "inbox_rule_changes",
    "subject_entropy",
    "body_length_ratio",
]
