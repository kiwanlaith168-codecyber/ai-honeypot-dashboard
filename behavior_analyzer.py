"""
behavior_analyzer.py — Behavioral Analysis Engine (NEW in v2.0)
─────────────────────────────────────────────────────────────────
Analyses HOW an attacker behaves, not just WHAT commands they ran.

Produces:
  • SessionMetadata   — timing, speed, automation signals
  • AttackerProfile   — bot / script_kiddie / experienced_human
  • AttackPhase       — recon / exploitation / post_compromise
  • Evidence list     — specific observations driving each conclusion
"""

import logging
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from config import (
    BOT_CMD_PER_MIN, SCRIPT_CMD_PER_MIN,
    AUTOMATION_DELAY_THRESHOLD, MIN_COMMANDS_FOR_ANALYSIS,
    RECON_PHASE_MAX_CMDS, EXPLOIT_PHASE_SCORE,
)

logger = logging.getLogger("honeypot.behavior")

# ─────────────────────────────────────────────────────────────────────────────
#  Data Structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CommandEvent:
    """A single command with its timing information."""
    seq:       int
    command:   str
    timestamp: float   # Unix time (seconds)
    delay_sec: float   # seconds since previous command (0 for first)


@dataclass
class SessionMetadata:
    """Collected behavioral metrics for one SSH session."""
    session_id:          int
    total_commands:      int       = 0
    session_duration:    float     = 0.0   # seconds
    commands_per_min:    float     = 0.0
    avg_cmd_delay_sec:   float     = 0.0
    min_cmd_delay_sec:   float     = 0.0
    max_cmd_delay_sec:   float     = 0.0
    unique_commands:     int       = 0
    unique_ratio:        float     = 0.0   # unique / total
    error_count:         int       = 0     # "command not found" responses
    sensitive_file_hits: int       = 0     # /etc/shadow, /root/*, etc.
    automation_score:    float     = 0.0   # 0–100, higher = more automated
    attacker_type:       str       = "unknown"   # bot | script_kiddie | experienced_human
    attack_phase:        str       = "unknown"   # recon | exploitation | post_compromise
    phase_confidence:    float     = 0.0   # 0–100
    evidence:            List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
#  Sensitive target patterns (for counting hits)
# ─────────────────────────────────────────────────────────────────────────────
SENSITIVE_PATTERNS = [
    "/etc/shadow", "/etc/sudoers", "/root/", "id_rsa", "id_ecdsa",
    ".ssh/", "authorized_keys", ".bash_history", "config.yml",
    "config.yaml", "config.json", ".env", "credentials", ".pem",
    ".key", "secret", "password", "token",
]

# Commands that indicate post-compromise activity
POST_COMPROMISE_CMDS = {
    "useradd", "adduser", "usermod", "crontab", "nc", "ncat",
    "wget", "curl", "python", "python3", "perl", "php", "bash",
    "chmod", "chown", "scp", "rsync",
}

EXPLOIT_CMDS = {
    "sudo", "su", "chmod", "chown", "find", "pkexec",
    "base64", "perl", "python", "php",
}


# ─────────────────────────────────────────────────────────────────────────────
#  Core Analysis Function
# ─────────────────────────────────────────────────────────────────────────────

def analyze_behavior(
    session_id: int,
    events: List[CommandEvent],
    session_duration: float,
    attack_type_counts: dict,
    risk_score: int,
) -> SessionMetadata:
    """
    Main entry point. Takes the full list of CommandEvents from a session
    and returns a fully populated SessionMetadata.
    """
    meta = SessionMetadata(session_id=session_id)
    meta.session_duration = session_duration

    if not events:
        meta.attacker_type = "unknown"
        meta.attack_phase  = "unknown"
        return meta

    # ── Basic counts ──────────────────────────────────────────────────────────
    meta.total_commands  = len(events)
    cmds_text            = [e.command for e in events]
    meta.unique_commands = len(set(cmds_text))
    meta.unique_ratio    = meta.unique_commands / max(meta.total_commands, 1)

    # ── Timing metrics ────────────────────────────────────────────────────────
    delays = [e.delay_sec for e in events if e.delay_sec > 0]
    if delays:
        meta.avg_cmd_delay_sec = sum(delays) / len(delays)
        meta.min_cmd_delay_sec = min(delays)
        meta.max_cmd_delay_sec = max(delays)
    else:
        meta.avg_cmd_delay_sec = 0.0

    minutes = max(session_duration / 60, 0.017)   # at least 1 second
    meta.commands_per_min = meta.total_commands / minutes

    # ── Sensitive file hits ───────────────────────────────────────────────────
    for cmd in cmds_text:
        if any(p in cmd.lower() for p in SENSITIVE_PATTERNS):
            meta.sensitive_file_hits += 1

    # ── Automation score (0–100) ──────────────────────────────────────────────
    automation_signals = []

    speed_score = min(meta.commands_per_min / BOT_CMD_PER_MIN * 50, 50)
    automation_signals.append(speed_score)

    if meta.avg_cmd_delay_sec < AUTOMATION_DELAY_THRESHOLD and delays:
        delay_score = (1 - meta.avg_cmd_delay_sec / AUTOMATION_DELAY_THRESHOLD) * 30
        automation_signals.append(delay_score)
    else:
        automation_signals.append(0)

    # Low unique ratio = running a fixed script
    if meta.unique_ratio < 0.5 and meta.total_commands >= MIN_COMMANDS_FOR_ANALYSIS:
        automation_signals.append(20)
    else:
        automation_signals.append(0)

    meta.automation_score = min(sum(automation_signals), 100)

    # ── Attacker type classification ──────────────────────────────────────────
    evidence = []

    if meta.commands_per_min >= BOT_CMD_PER_MIN:
        meta.attacker_type = "automated_bot"
        evidence.append(
            f"Speed {meta.commands_per_min:.1f} cmds/min exceeds bot threshold "
            f"({BOT_CMD_PER_MIN})"
        )
        if meta.avg_cmd_delay_sec < 0.2:
            evidence.append(
                f"Average inter-command delay {meta.avg_cmd_delay_sec:.3f}s — "
                f"near-instant, consistent with automation"
            )

    elif meta.commands_per_min >= SCRIPT_CMD_PER_MIN:
        meta.attacker_type = "script_kiddie"
        evidence.append(
            f"Speed {meta.commands_per_min:.1f} cmds/min suggests scripted "
            f"but not fully automated attack"
        )
        if meta.unique_ratio < 0.6:
            evidence.append(
                f"Low command variety ({meta.unique_ratio:.0%} unique) — "
                f"likely running a pre-written attack script"
            )

    else:
        meta.attacker_type = "experienced_human"
        evidence.append(
            f"Deliberate pace {meta.commands_per_min:.1f} cmds/min with variable "
            f"delays — consistent with manual operation"
        )
        if meta.unique_ratio > 0.75:
            evidence.append(
                f"High command diversity ({meta.unique_ratio:.0%} unique) — "
                f"indicates adaptive, exploratory behaviour"
            )
        if meta.sensitive_file_hits > 2:
            evidence.append(
                f"Targeted {meta.sensitive_file_hits} sensitive files — "
                f"demonstrates system knowledge"
            )

    # ── Attack phase detection ────────────────────────────────────────────────
    cmd_set       = set(c.split()[0] for c in cmds_text if c.strip())
    has_post      = bool(cmd_set & POST_COMPROMISE_CMDS)
    has_exploit   = bool(cmd_set & EXPLOIT_CMDS)
    recon_only    = attack_type_counts.get("recon", 0) > 0 and len(attack_type_counts) == 1

    if risk_score >= EXPLOIT_PHASE_SCORE and has_post:
        meta.attack_phase    = "post_compromise"
        meta.phase_confidence = 85.0
        evidence.append(
            "Post-compromise tools detected (cron, netcat, wget, new user creation) "
            "alongside high risk score"
        )
    elif risk_score >= EXPLOIT_PHASE_SCORE or has_exploit:
        meta.attack_phase    = "exploitation"
        meta.phase_confidence = 78.0
        evidence.append(
            f"Risk score {risk_score} with exploitation commands indicates active "
            f"intrusion attempt"
        )
    elif recon_only and meta.total_commands <= RECON_PHASE_MAX_CMDS:
        meta.attack_phase    = "reconnaissance"
        meta.phase_confidence = 90.0
        evidence.append(
            f"Only reconnaissance commands in {meta.total_commands}-command session — "
            f"initial system profiling"
        )
    else:
        meta.attack_phase    = "reconnaissance"
        meta.phase_confidence = 60.0
        evidence.append("Mixed or limited commands — classified as reconnaissance phase")

    meta.evidence = evidence
    logger.debug(
        "Behavior: session=%d type=%s phase=%s auto=%.0f cmds/min=%.1f",
        session_id, meta.attacker_type, meta.attack_phase,
        meta.automation_score, meta.commands_per_min,
    )
    return meta


# ─────────────────────────────────────────────────────────────────────────────
#  Live (mid-session) running score helper
# ─────────────────────────────────────────────────────────────────────────────

class LiveSessionTracker:
    """
    Lightweight tracker updated on every command during an active session.
    Used by FakeShell for real-time risk escalation and SSE events.
    """

    def __init__(self, session_id: int, ip: str):
        self.session_id     = session_id
        self.ip             = ip
        self.running_score  = 0
        self.type_counts:   dict = {}
        self.alerted        = False   # has a mid-session alert already been fired?
        self._cmd_times:    list = []
        self.command_events: List[CommandEvent] = []

    def add_command(self, seq: int, command: str, timestamp: float,
                    attack_types: list) -> dict:
        """
        Register one command. Returns a dict with live status for SSE push.
        """
        delay = (timestamp - self._cmd_times[-1]) if self._cmd_times else 0.0
        self._cmd_times.append(timestamp)

        evt = CommandEvent(seq=seq, command=command,
                           timestamp=timestamp, delay_sec=delay)
        self.command_events.append(evt)

        from config import RISK_WEIGHTS
        for t in attack_types:
            self.type_counts[t] = self.type_counts.get(t, 0) + 1
            self.running_score  += RISK_WEIGHTS.get(t, 1)

        return {
            "session_id":    self.session_id,
            "ip":            self.ip,
            "command":       command,
            "attack_types":  attack_types,
            "running_score": self.running_score,
            "seq":           seq,
        }
