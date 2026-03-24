from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "bec_platform.db"

FEATURE_NAMES = [
    "login_time_delta_hours",
    "location_distance_km",
    "emails_per_hour",
    "recipient_count",
    "inbox_rule_changes",
    "subject_entropy",
    "body_length_ratio",
]
