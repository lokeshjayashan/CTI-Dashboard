"""
Central configuration for the CTI Dashboard.
API keys are read from environment variables with empty-string fallbacks.
"""
import os

# ── External API Keys ──────────────────────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# ── MongoDB ────────────────────────────────────────────────────────
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = "cti_dashboard"

# Collection names
COLLECTION_THREAT_INTEL = "threat_intel"
COLLECTION_API_CACHE = "api_cache"
COLLECTION_TOPICS = "topics"

# ── Cache ──────────────────────────────────────────────────────────
CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours

# ── AI Models ──────────────────────────────────────────────────────
CLASSIFIER_MODEL = "facebook/bart-large-mnli"
THREAT_CATEGORIES = [
    "malware",
    "phishing",
    "botnet",
    "DDoS",
    "spam",
    "ransomware",
]

# ── Flask ──────────────────────────────────────────────────────────
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_DEBUG = True
