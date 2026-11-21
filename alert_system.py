"""
alert_system.py — Multi-channel Alert System v2.0
NEW: fire_live_alert() for mid-session risk escalation
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from config import (
    ALERT_MIN_RISK, ALERT_LOG_PATH,
    SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, ALERT_RECIPIENTS,
)
import database as db
from geo import resolve_ip

logger = logging.getLogger("honeypot.alerts")
_SEVERITY = {"Low": 0, "Medium": 1, "High": 2}


def _should_alert(risk_level):
    return _SEVERITY.get(risk_level, 0) >= _SEVERITY.get(ALERT_MIN_RISK, 1)


def _format_alert(ip, geo, analysis, session_id, is_live=False):
    types  = ", ".join(analysis.get("attack_types", ["unknown"]))
    recs   = analysis.get("recommendations", "N/A")
    ts     = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    prefix = "🚨 LIVE MID-SESSION ALERT" if is_live else "🚨 HONEYPOT ALERT"
    return (
        f"\n{'='*62}\n"
        f"{prefix} — {analysis.get('risk_level','?').upper()} RISK\n"
        f"{'='*62}\n"
        f"  Timestamp    : {ts}\n"
        f"  Session      : #{session_id}\n"
        f"  IP Address   : {ip}\n"
        f"  Country      : {geo.get('country','Unknown')} ({geo.get('countryCode','??')})\n"
        f"  City/Region  : {geo.get('city','')} / {geo.get('regionName','')}\n"
        f"  ISP          : {geo.get('isp','Unknown')}\n"
        f"  Attack Types : {types}\n"
        f"  Attacker Type: {analysis.get('attacker_type','unknown')}\n"
        f"  Attack Phase : {analysis.get('attack_phase','unknown')}\n"
        f"  Risk Level   : {analysis.get('risk_level','Low')}  (score={analysis.get('risk_score',0)})\n"
        f"  Commands     : {analysis.get('command_count', 0)}\n"
        f"\n  Recommendations:\n  {recs}\n"
        f"{'='*62}\n"
    )


def _write_log(msg):
    try:
        with open(ALERT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except Exception as exc:
        logger.error("Alert log write failed: %s", exc)


def _send_email(subject, body):
    if not SMTP_SERVER or not ALERT_RECIPIENTS:
        return
    try:
        msg = MIMEMultipart()
        msg["From"]    = SMTP_USER
        msg["To"]      = ", ".join(ALERT_RECIPIENTS)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASSWORD)
            s.sendmail(SMTP_USER, ALERT_RECIPIENTS, msg.as_string())
    except Exception as exc:
        logger.error("Email alert failed: %s", exc)


def check_and_alert(session_id, ip, analysis):
    """Called after session ends. Fires full alert if risk threshold met."""
    risk = analysis.get("risk_level", "Low")
    if not _should_alert(risk):
        return

    geo     = resolve_ip(ip)
    message = _format_alert(ip, geo, analysis, session_id)
    country = geo.get("country", "Unknown")
    primary = analysis.get("primary_type", "unknown")

    logger.warning(message)
    _write_log(message)
    db.save_alert(session_id, ip, country, primary, risk, message, is_live=False)
    _send_email(f"[HONEYPOT] {risk} Risk — {ip} ({country})", message)


def fire_live_alert(session_id, ip, running_score, trigger_cmd):
    """
    Called MID-SESSION when running risk score crosses the threshold.
    Uses a lightweight analysis stub (no full session data yet).
    """
    geo     = resolve_ip(ip)
    country = geo.get("country", "Unknown")

    analysis = {
        "attack_types":  ["in-progress"],
        "primary_type":  "escalating",
        "risk_level":    "High",
        "risk_score":    running_score,
        "attacker_type": "unknown",
        "attack_phase":  "exploitation",
        "recommendations": "• Session is ACTIVE — monitor closely\n• Prepare to block IP at firewall\n• Capture full session log for forensics",
        "command_count": 0,
    }

    ts  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    msg = (
        f"\n{'='*62}\n"
        f"⚡ LIVE ALERT — HIGH RISK SESSION IN PROGRESS\n"
        f"{'='*62}\n"
        f"  Timestamp   : {ts}\n"
        f"  Session     : #{session_id}\n"
        f"  IP          : {ip} ({country})\n"
        f"  Trigger Cmd : {trigger_cmd}\n"
        f"  Running Score: {running_score} (High threshold crossed)\n"
        f"  Status      : Session STILL ACTIVE\n"
        f"{'='*62}\n"
    )
    logger.warning(msg)
    _write_log(msg)
    db.save_alert(
        session_id, ip, country,
        "live_escalation", "High", msg, is_live=True,
    )
