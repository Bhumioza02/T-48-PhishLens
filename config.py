"""
PhishLens - Configuration and Settings
"Scan before you trust."
"""
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = BASE_DIR / "phishlens.db"
TRUSTED_BRANDS_PATH = DATA_DIR / "trusted_brands.json"

# Application Metadata
APP_NAME = "PHISHLENS"
TAGLINE = "Scan before you trust."
SUBTITLE = "3-Second Security Check for URLs and QR Codes"
APP_VERSION = "0.1.0-alpha"

# Security Verdicts
VERDICT_SAFE = "SAFE"
VERDICT_CAUTION = "CAUTION"
VERDICT_DANGER = "DANGER"

# Risk Thresholds (Score: 0 to 100)
# 0-30: Safe, 31-69: Caution, 70+: Danger
RISK_THRESHOLD_SAFE = 30
RISK_THRESHOLD_DANGER = 70

# UI Theme Color Palette (Modern Dark Cybersecurity SaaS)
COLORS = {
    "bg_dark": "#0B0F19",
    "card_bg": "rgba(17, 24, 39, 0.75)",
    "card_border": "rgba(56, 189, 248, 0.2)",
    "accent_cyan": "#00F0FF",
    "accent_blue": "#38BDF8",
    "safe_green": "#10B981",
    "caution_amber": "#F59E0B",
    "danger_red": "#EF4444",
    "text_main": "#F8FAFC",
    "text_muted": "#94A3B8",
}

# SSRF and Network Guardrails
HTTP_TIMEOUT_SECONDS = 5
MAX_REDIRECTS = 5
ALLOWED_SCHEMES = ("http", "https")
BLOCKED_HOSTNAMES = (
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "169.254.169.254",  # Cloud metadata
)

# Domain Analysis & Typosquatting Detection Settings
TYPOSQUAT_SIMILARITY_THRESHOLD = 0.80
MAX_LEVENSHTEIN_DISTANCE = 2
MIN_BRAND_LENGTH_FOR_FUZZY = 4

