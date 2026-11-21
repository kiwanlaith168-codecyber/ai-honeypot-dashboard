"""
config.py — Central configuration for the AI-Powered Honeypot System v2.0
"""

import os
import secrets

try:  # optional: load variables from a local .env file (never commit it)
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
DATA_DIR      = os.path.join(BASE_DIR, "data")
LOG_DIR       = os.path.join(BASE_DIR, "logs")
REPORT_DIR    = os.path.join(BASE_DIR, "reports")
STATIC_DIR    = os.path.join(BASE_DIR, "static")
TEMPLATE_DIR  = os.path.join(BASE_DIR, "templates")

for d in [DATA_DIR, LOG_DIR, REPORT_DIR]:
    os.makedirs(d, exist_ok=True)

# ── Honeypot SSH ──────────────────────────────────────────────────────────────
HONEYPOT_HOST       = "0.0.0.0"
HONEYPOT_PORT       = 2222
HONEYPOT_USERNAME   = "zarqa"
HONEYPOT_PASSWORD   = "2026"
HONEYPOT_BANNER     = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
FAKE_HOSTNAME       = "ubuntu-server"
FAKE_OS             = "Ubuntu 22.04.3 LTS"
MAX_SESSIONS        = 50

# ── Database ──────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(DATA_DIR, "honeypot.db")

# ── Flask Dashboard ───────────────────────────────────────────────────────────
FLASK_HOST       = os.environ.get("FLASK_HOST", "127.0.0.1")   # dashboard: localhost only by default
FLASK_PORT       = 5000
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
ADMIN_USERNAME   = os.environ.get("ADMIN_USERNAME", "admin")
_admin_pw        = os.environ.get("ADMIN_PASSWORD")
ADMIN_PASSWORD_GENERATED = not _admin_pw
ADMIN_PASSWORD   = _admin_pw or secrets.token_urlsafe(12)   # random per run if not set

# ── Geolocation ───────────────────────────────────────────────────────────────
GEO_API_URL   = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,query"
GEO_TIMEOUT   = 5
GEO_CACHE_TTL = 3600

# ── AI Risk Weights & Thresholds ──────────────────────────────────────────────
RISK_WEIGHTS = {
    "recon":                1,
    "brute_force":          3,
    "privilege_escalation": 4,
    "malware_download":     5,
    "lateral_movement":     4,
    "data_exfiltration":    5,
    "persistence":          4,
    "unknown":              1,
}

RISK_THRESHOLDS = {
    "Low":    (0,  4),
    "Medium": (5,  9),
    "High":   (10, 9999),
}

# ── Behavioral Analysis ───────────────────────────────────────────────────────
AUTOMATION_CMD_PER_MIN     = 20    # cmds/min above this = automated
AUTOMATION_DELAY_THRESHOLD = 0.8   # avg delay below this (sec) = automated
MIN_COMMANDS_FOR_ANALYSIS  = 3

BOT_CMD_PER_MIN            = 30    # >= this → bot
SCRIPT_CMD_PER_MIN         = 12    # >= this → script kiddie (below = human)

RECON_PHASE_MAX_CMDS       = 6
EXPLOIT_PHASE_SCORE        = 8

LIVE_RISK_ALERT_THRESHOLD  = 8     # fire mid-session alert if running score >= this

# ── LLM Integration (Groq / Google AI — Optional) ────────────────────────────
# Groq API key: set GROQ_API_KEY in your environment or .env file. Never hard-code it.
GROQ_API_KEY    = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL      = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_API_URL    = "https://api.groq.com/openai/v1/chat/completions"
GROQ_TIMEOUT    = 15
GROQ_MAX_TOKENS = 450

GOOGLE_AI_KEY   = os.environ.get("GOOGLE_AI_KEY", "")
GOOGLE_AI_MODEL = "gemini-1.5-flash"
GOOGLE_AI_URL   = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

# Auto-detect which provider is available
LLM_PROVIDER = "groq" if GROQ_API_KEY else ("google" if GOOGLE_AI_KEY else "none")

# ── Alerts ────────────────────────────────────────────────────────────────────
ALERT_MIN_RISK   = "Medium"
ALERT_LOG_PATH   = os.path.join(LOG_DIR, "alerts.log")
SMTP_SERVER      = ""
SMTP_PORT        = 587
SMTP_USER        = ""
SMTP_PASSWORD    = ""
ALERT_RECIPIENTS = []

# ── Reports ───────────────────────────────────────────────────────────────────
REPORT_SCHEDULE_HOUR = 23
PDF_LOGO_TEXT        = "AI HONEYPOT SYSTEM v2.0"
ORGANIZATION_NAME    = "Zarqa University — Cybersecurity Lab"