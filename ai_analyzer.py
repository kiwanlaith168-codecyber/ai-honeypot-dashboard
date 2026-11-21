"""
ai_analyzer.py — Hybrid AI Analysis Engine v2.0
─────────────────────────────────────────────────
Layer 1: Rule-based command classification (unchanged from v1)
Layer 2: Behavioral analysis (new — behavior_analyzer.py)
Layer 3: LLM narrative generation (new — llm_client.py)

Evidence-based recommendations: every recommendation now cites
the specific commands that triggered it.
"""

import re
import json
import logging
from datetime import datetime
from config import RISK_WEIGHTS, RISK_THRESHOLDS
import database as db

logger = logging.getLogger("honeypot.ai")

# ─────────────────────────────────────────────────────────────────────────────
#  Attack Signature Patterns (Layer 1 — unchanged)
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_PATTERNS = {
    "recon": {
        "patterns": [
            r"^(uname|hostname|whoami|id|pwd|ls|cat\s+/etc/os-release)",
            r"cat\s+(/etc/passwd|/etc/hosts|/proc/version|/etc/os-release)",
            r"(ifconfig|ip\s+addr|ip\s+route|netstat|ss)",
            r"(ps\s+aux|top|df|free|uptime|lsof)",
            r"(find\s+/|locate\s+)",
            r"(dpkg\s+-l|apt\s+list|rpm\s+-qa|yum\s+list)",
            r"(env|export|printenv)",
            r"(history|\.bash_history)",
            r"(crontab\s+-l|cat\s+/etc/cron)",
            r"cat\s+/var/log",
            r"(nmap|masscan)",
        ],
        "weight": 1,
        "description": "System reconnaissance and information gathering",
    },
    "brute_force": {
        "patterns": [
            r"(hydra|medusa|john|hashcat|crunch|aircrack)",
            r"(passwd|shadow|unshadow)",
            r"(su\s+-|sudo\s+su|sudo\s+-s|sudo\s+-i)",
            r"for\s+\w+\s+in.*do.*ssh",
            r"(ssh\s+-o|ssh\s+root@|sshpass)",
        ],
        "weight": 3,
        "description": "Credential brute-force or password cracking",
    },
    "privilege_escalation": {
        "patterns": [
            r"(sudo|su\s+root|sudo\s+-l|sudo\s+bash|sudo\s+sh)",
            r"(chmod\s+[0-7]*[67][0-7]{2}|chmod\s+\+s|chmod\s+4[0-9]{3})",
            r"(chown\s+root|chgrp\s+root)",
            r"(\/etc\/sudoers|visudo|NOPASSWD)",
            r"(exploit|buffer.overflow|shellcode|payload)",
            r"(pkexec|polkit|dirtycow|dirty_cow)",
            r"echo\s+.*>>\s*\/etc\/",
            r"(useradd|adduser|usermod)\s+.*-G\s+(sudo|wheel|root)",
        ],
        "weight": 4,
        "description": "Privilege escalation to root",
    },
    "malware_download": {
        "patterns": [
            r"(wget|curl|fetch)\s+http",
            r"(wget|curl).*(-O|-o)\s+\S+",
            r"(python|perl|ruby|php).*(-c|-e)\s+['\"]",
            r"base64\s+-d",
            r"(chmod\s+\+x|chmod\s+777)\s+\S+",
            r"(\.\/\w+|bash\s+\w+\.sh|sh\s+\w+)",
            r"(meterpreter|metasploit|msfvenom|msf)",
            r"(nc\s+-e|ncat\s+-e|bash\s+-i\s+>&|\/dev\/tcp)",
            r"(pip\s+install|gem\s+install|npm\s+install)\s+",
        ],
        "weight": 5,
        "description": "Malware download or execution attempt",
    },
    "lateral_movement": {
        "patterns": [
            r"(ssh\s+\d{1,3}\.\d{1,3}|ssh\s+\w+@)",
            r"(scp\s+|rsync\s+.*@)",
            r"cat\s+.*id_rsa",
            r"(\/\.ssh\/|authorized_keys|known_hosts)",
            r"(ping\s+|nmap\s+|arp\s+)",
        ],
        "weight": 4,
        "description": "Lateral movement through the network",
    },
    "data_exfiltration": {
        "patterns": [
            r"(mysqldump|pg_dump|mongodump)",
            r"(tar\s+.*z.*|zip\s+|7z\s+)",
            r"(curl|wget).*\s+-d\s+",
            r"(cat|grep).*passwd.*>",
            r"find\s+.*-name\s+['\"]?\*\.(conf|cfg|key|pem|env)['\"]?",
            r"(cat|head|tail|strings)\s+.*\.(key|pem|crt|p12)",
        ],
        "weight": 5,
        "description": "Data exfiltration or sensitive file access",
    },
    "persistence": {
        "patterns": [
            r"crontab\s+-e",
            r"echo\s+.*>>\s*(\/etc\/rc\.local|\/etc\/crontab)",
            r"(systemctl\s+enable|update-rc\.d)",
            r"(echo|cat).*>>\s*\/(home|root)\/.*\/(\.bashrc|\.bash_profile|\.profile)",
            r"echo\s+.*>>\s*\/etc\/passwd",
            r"(ln\s+-s.*\/etc\/init\.d|cp.*\/etc\/init\.d)",
        ],
        "weight": 4,
        "description": "Persistence mechanism installation",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
#  Evidence-Based Recommendations (v2.0 — include triggering commands)
# ─────────────────────────────────────────────────────────────────────────────

# Each recommendation is a tuple: (advice_text, triggered_by_pattern_hint)
EVIDENCE_RECOMMENDATIONS = {
    "recon": [
        ("Minimize SSH banner verbosity and disable unnecessary service fingerprinting.",
         "system info commands (uname, hostname, cat /etc/os-release)"),
        ("Enable honeypot deception layers — fake files and misleading system info.",
         "file and directory enumeration"),
        ("Review what information is exposed: /etc/passwd, process listings, network config.",
         "cat /etc/passwd, ps aux, netstat"),
    ],
    "brute_force": [
        ("Implement SSH account lockout after 3 failed attempts using pam_faillock or fail2ban.",
         "repeated sudo/su attempts"),
        ("Disable password authentication — enforce SSH key-only login.",
         "password-based login attempts"),
        ("Deploy multi-factor authentication (MFA) on all privileged accounts.",
         "credential stuffing pattern detected"),
    ],
    "privilege_escalation": [
        ("Audit /etc/sudoers immediately — remove NOPASSWD entries and unnecessary sudo rights.",
         "sudo -l enumeration and sudo bash attempts"),
        ("Apply latest kernel and system patches — check for local privilege escalation CVEs.",
         "exploitation commands detected"),
        ("Deploy Mandatory Access Control (SELinux or AppArmor) to limit privilege boundaries.",
         "privilege escalation commands"),
        ("Monitor /etc/passwd and /etc/sudoers with file integrity monitoring (FIM).",
         "sensitive config file access"),
    ],
    "malware_download": [
        ("Block all outbound connections from servers — implement strict egress firewall rules.",
         "wget/curl to external URLs"),
        ("Restrict execute permissions on /tmp and /var/tmp — common malware staging areas.",
         "chmod +x on downloaded files"),
        ("Deploy an Endpoint Detection & Response (EDR) agent with real-time execution monitoring.",
         "script execution and download attempts"),
        ("Implement application whitelisting — only allow approved binaries to execute.",
         "arbitrary script execution"),
    ],
    "lateral_movement": [
        ("Rotate and audit all SSH private keys — revoke any that may be compromised.",
         "cat ~/.ssh/id_rsa access"),
        ("Segment the network — servers should not be able to SSH to each other without MFA.",
         "SSH connection attempts to internal IPs"),
        ("Implement Zero Trust Network Architecture — verify every connection.",
         "lateral movement commands"),
        ("Monitor for unusual outbound SSH connections using network flow analysis.",
         "network scanning and pivoting"),
    ],
    "data_exfiltration": [
        ("Encrypt sensitive data at rest — database dumps should be worthless without keys.",
         "mysqldump and database access commands"),
        ("Implement Data Loss Prevention (DLP) — alert on bulk file access or transfers.",
         "file archiving and transfer commands"),
        ("Rotate all database credentials and API keys immediately.",
         "config file and credential access"),
    ],
    "persistence": [
        ("Audit all crontabs (user and system), rc.local, and systemd units now.",
         "crontab -e and crontab modification"),
        ("Monitor shell startup files (.bashrc, .bash_profile) for unauthorized modifications.",
         "echo >> .bashrc persistence technique"),
        ("Review /etc/passwd and /etc/shadow for unauthorized user accounts.",
         "useradd/adduser commands"),
    ],
    "unknown": [
        ("Monitor this IP address across all systems for 48 hours.",
         "unclassified activity"),
        ("Review raw session logs for manual threat hunting.",
         "commands did not match known patterns"),
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
#  Core Classification
# ─────────────────────────────────────────────────────────────────────────────

def classify_command(command: str) -> list:
    """Return list of attack type names that match this command."""
    cmd_lower = command.lower()
    matches = []
    for atype, cfg in ATTACK_PATTERNS.items():
        for pat in cfg["patterns"]:
            if re.search(pat, cmd_lower):
                matches.append(atype)
                break
    return matches


def _score_and_level(type_counts: dict) -> tuple:
    score = sum(RISK_WEIGHTS.get(t, 1) * cnt for t, cnt in type_counts.items())
    for level, (lo, hi) in RISK_THRESHOLDS.items():
        if lo <= score <= hi:
            return score, level
    return score, "High"


def _primary_type(type_counts: dict) -> str:
    if not type_counts:
        return "unknown"
    return max(type_counts, key=lambda t: RISK_WEIGHTS.get(t, 1) * type_counts[t])


# ─────────────────────────────────────────────────────────────────────────────
#  Evidence-Based Recommendation Builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_evidence_recommendations(
    attack_types: list,
    commands: list,
    type_counts: dict,
) -> str:
    """
    Build recommendations that cite specific evidence from the session.
    Each recommendation references the actual commands that triggered it.
    """
    lines = []
    seen  = set()

    # Find triggering commands for each type
    type_examples: dict = {}
    for t in attack_types:
        examples = []
        cfg = ATTACK_PATTERNS.get(t, {})
        for cmd in commands:
            for pat in cfg.get("patterns", []):
                if re.search(pat, cmd.lower()) and cmd not in examples:
                    examples.append(cmd)
                    if len(examples) >= 2:
                        break
            if len(examples) >= 2:
                break
        type_examples[t] = examples

    for atype in attack_types[:5]:   # top 5 attack types
        recs = EVIDENCE_RECOMMENDATIONS.get(atype,
               EVIDENCE_RECOMMENDATIONS["unknown"])
        examples = type_examples.get(atype, [])
        cnt = type_counts.get(atype, 0)

        for advice, trigger_hint in recs[:2]:
            if advice in seen:
                continue
            seen.add(advice)

            # Build evidence citation
            if examples:
                ex_str = " / ".join(f'"{e}"' for e in examples[:2])
                citation = f" [Evidence: {ex_str} — {cnt}x detected]"
            else:
                citation = f" [Triggered by: {trigger_hint}]"

            lines.append(f"• {advice}{citation}")

    return "\n".join(lines) if lines else "• Monitor system for further suspicious activity."


# ─────────────────────────────────────────────────────────────────────────────
#  Main Analysis Function
# ─────────────────────────────────────────────────────────────────────────────

def analyze_session(
    session_id: int,
    commands: list,
    command_events=None,      # List[CommandEvent] from LiveSessionTracker
    session_duration: float = 0.0,
) -> dict:
    """
    Full hybrid analysis of a completed session.
    Integrates: rule-based (Layer 1) + behavioral (Layer 2) + LLM (Layer 3)
    """
    # ── Layer 1: Rule-based classification ───────────────────────────────────
    type_counts: dict = {}
    for cmd in commands:
        for atype in classify_command(cmd):
            type_counts[atype] = type_counts.get(atype, 0) + 1

    if not type_counts:
        type_counts["unknown"] = 1

    risk_score, risk_level = _score_and_level(type_counts)
    primary_type           = _primary_type(type_counts)
    attack_types           = sorted(
        type_counts.keys(),
        key=lambda t: -RISK_WEIGHTS.get(t, 1)
    )

    recommendations = _build_evidence_recommendations(
        attack_types, commands, type_counts
    )

    # ── Layer 2: Behavioral analysis ─────────────────────────────────────────
    attacker_type     = "unknown"
    attack_phase      = "unknown"
    behavior_evidence = []
    behavioral_meta   = {}

    try:
        from behavior_analyzer import analyze_behavior, CommandEvent
        events = command_events or []

        if not events and commands:
            # Build minimal events from commands list (no timing)
            import time
            now = time.time()
            events = [
                CommandEvent(seq=i+1, command=c,
                             timestamp=now + i, delay_sec=1.0)
                for i, c in enumerate(commands)
            ]

        meta = analyze_behavior(
            session_id, events, session_duration,
            type_counts, risk_score
        )
        attacker_type     = meta.attacker_type
        attack_phase      = meta.attack_phase
        behavior_evidence = meta.evidence
        behavioral_meta   = meta.to_dict()

        # Save behavioral data to sessions table
        db.update_session_behavior(session_id, behavioral_meta)

    except Exception as exc:
        logger.warning("Behavioral analysis failed: %s", exc)

    # ── Layer 3: LLM narrative ────────────────────────────────────────────────
    ai_narrative  = ""
    llm_provider  = "fallback"

    try:
        session_row = db.get_session_by_id(session_id)
        from llm_client import get_llm_analysis
        facts = {
            "ip":               session_row.get("ip_address", "unknown"),
            "country":          session_row.get("country", "unknown"),
            "isp":              session_row.get("isp", "unknown"),
            "duration_sec":     session_duration,
            "commands":         commands,
            "attack_types":     attack_types,
            "primary_type":     primary_type,
            "risk_level":       risk_level,
            "risk_score":       risk_score,
            "attacker_type":    attacker_type,
            "attack_phase":     attack_phase,
            "automation_score": behavioral_meta.get("automation_score", 0),
            "sensitive_file_hits": behavioral_meta.get("sensitive_file_hits", 0),
            "commands_per_min": behavioral_meta.get("commands_per_min", 0),
            "evidence":         behavior_evidence,
        }
        result       = get_llm_analysis(facts)
        ai_narrative = result["narrative"]
        llm_provider = result["provider"]

    except Exception as exc:
        logger.warning("LLM analysis failed: %s", exc)
        ai_narrative = f"Rule-based analysis: {primary_type.replace('_',' ').title()} attack, {risk_level} risk (score {risk_score})."

    # ── Assemble final result ─────────────────────────────────────────────────
    analysis = {
        "session_id":        session_id,
        "attack_types":      attack_types,
        "type_counts":       type_counts,
        "primary_type":      primary_type,
        "risk_level":        risk_level,
        "risk_score":        risk_score,
        "recommendations":   recommendations,
        "ai_narrative":      ai_narrative,
        "llm_provider":      llm_provider,
        "attacker_type":     attacker_type,
        "attack_phase":      attack_phase,
        "behavior_evidence": behavior_evidence,
        "command_count":     len(commands),
        "analyzed_at":       datetime.utcnow().isoformat(),
    }

    db.save_attack_analysis(session_id, analysis)

    logger.info(
        "Analysis done  session=%d  risk=%s(%d)  type=%s  "
        "profile=%s  phase=%s  llm=%s",
        session_id, risk_level, risk_score, primary_type,
        attacker_type, attack_phase, llm_provider,
    )
    return analysis
