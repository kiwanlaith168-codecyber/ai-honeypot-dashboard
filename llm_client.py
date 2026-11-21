"""
llm_client.py — LLM Integration Layer (NEW in v2.0)
─────────────────────────────────────────────────────
Supports: Groq (llama3-70b) and Google AI Studio (gemini-1.5-flash)
Falls back gracefully to rule-based text if no API key is configured
or if the API call fails.

Usage:
    from llm_client import get_llm_analysis
    narrative = get_llm_analysis(session_facts)
"""

import json
import logging
import requests
from config import (
    LLM_PROVIDER,
    GROQ_API_KEY, GROQ_MODEL, GROQ_API_URL, GROQ_TIMEOUT, GROQ_MAX_TOKENS,
    GOOGLE_AI_KEY, GOOGLE_AI_MODEL, GOOGLE_AI_URL,
)

logger = logging.getLogger("honeypot.llm")


# ─────────────────────────────────────────────────────────────────────────────
#  Prompt Builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_prompt(facts: dict) -> str:
    """
    Construct a structured, concise prompt from session facts.
    facts keys: ip, country, isp, duration_sec, commands, attack_types,
                primary_type, risk_level, risk_score, attacker_type,
                attack_phase, automation_score, sensitive_file_hits,
                commands_per_min, evidence
    """
    cmds_sample = facts.get("commands", [])[:15]   # limit to first 15
    cmds_str    = "\n".join(f"  {i+1}. {c}" for i, c in enumerate(cmds_sample))
    if len(facts.get("commands", [])) > 15:
        cmds_str += f"\n  ... and {len(facts['commands']) - 15} more commands"

    evidence_str = "\n".join(f"  - {e}" for e in facts.get("evidence", []))

    prompt = f"""You are a senior cybersecurity analyst reviewing a honeypot intrusion session.

SESSION FACTS:
- Attacker IP: {facts.get('ip', 'unknown')} | Country: {facts.get('country', 'unknown')} | ISP: {facts.get('isp', 'unknown')}
- Session duration: {facts.get('duration_sec', 0):.0f} seconds
- Total commands: {len(facts.get('commands', []))} | Speed: {facts.get('commands_per_min', 0):.1f} cmds/min
- Attack types detected: {', '.join(facts.get('attack_types', ['unknown']))}
- Primary attack type: {facts.get('primary_type', 'unknown')}
- Risk level: {facts.get('risk_level', 'Low')} (score: {facts.get('risk_score', 0)})
- Attacker profile: {facts.get('attacker_type', 'unknown')}
- Attack phase: {facts.get('attack_phase', 'unknown')}
- Automation score: {facts.get('automation_score', 0):.0f}/100
- Sensitive files accessed: {facts.get('sensitive_file_hits', 0)}

COMMANDS EXECUTED:
{cmds_str}

BEHAVIORAL EVIDENCE:
{evidence_str}

Write a professional 3-paragraph security analysis (max 180 words total):
1. What this attacker was doing and their likely objective
2. Why this is classified as {facts.get('risk_level','unknown')} risk and what makes it dangerous
3. The single most important defensive action to take immediately

Be specific, reference the actual commands and evidence above. No generic advice."""

    return prompt


# ─────────────────────────────────────────────────────────────────────────────
#  Provider: Groq
# ─────────────────────────────────────────────────────────────────────────────

def _call_groq(prompt: str) -> str:
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type":  "application/json",
    }
    payload = {
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": GROQ_MAX_TOKENS,
        "temperature": 0.3,
    }
    resp = requests.post(GROQ_API_URL, headers=headers,
                         json=payload, timeout=GROQ_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


# ─────────────────────────────────────────────────────────────────────────────
#  Provider: Google AI Studio (Gemini)
# ─────────────────────────────────────────────────────────────────────────────

def _call_google(prompt: str) -> str:
    url  = GOOGLE_AI_URL.format(model=GOOGLE_AI_MODEL)
    url  += f"?key={GOOGLE_AI_KEY}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "maxOutputTokens": GROQ_MAX_TOKENS,
            "temperature":     0.3,
        },
    }
    resp = requests.post(url, json=payload, timeout=GROQ_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    return data["candidates"][0]["content"]["parts"][0]["text"].strip()


# ─────────────────────────────────────────────────────────────────────────────
#  Rule-based Fallback Narrative
# ─────────────────────────────────────────────────────────────────────────────

def _fallback_narrative(facts: dict) -> str:
    """
    Generate a readable narrative without an LLM.
    Uses the behavioral evidence and attack types to produce structured text.
    """
    ip       = facts.get("ip", "unknown")
    country  = facts.get("country", "unknown")
    primary  = facts.get("primary_type", "unknown").replace("_", " ")
    risk     = facts.get("risk_level", "Low")
    score    = facts.get("risk_score", 0)
    a_type   = facts.get("attacker_type", "unknown").replace("_", " ")
    phase    = facts.get("attack_phase", "unknown").replace("_", " ")
    auto     = facts.get("automation_score", 0)
    cmds     = len(facts.get("commands", []))
    evidence = facts.get("evidence", [])

    ev_str = (" The behavioral evidence shows: " +
               " | ".join(evidence[:3]) + ".") if evidence else ""

    narrative = (
        f"The attacker from {ip} ({country}) conducted a {phase} session "
        f"classified as {primary}. With {cmds} commands executed, the session "
        f"was identified as originating from a {a_type} "
        f"(automation score: {auto:.0f}/100).{ev_str} "
        f"The overall risk assessment is {risk} with a score of {score}, "
        f"driven by the combination of attack techniques observed. "
        f"Immediate defensive action should focus on blocking this IP at "
        f"the firewall level and reviewing any systems accessible from this "
        f"network segment for signs of compromise."
    )
    return narrative


# ─────────────────────────────────────────────────────────────────────────────
#  Public API
# ─────────────────────────────────────────────────────────────────────────────

def get_llm_analysis(facts: dict) -> dict:
    """
    Generate an AI narrative for a completed session.

    Returns:
        {
          "narrative": str,      — the analysis text
          "provider":  str,      — "groq" | "google" | "fallback"
          "success":   bool,
        }
    """
    provider = LLM_PROVIDER

    if provider == "none":
        return {
            "narrative": _fallback_narrative(facts),
            "provider":  "fallback",
            "success":   True,
        }

    prompt = _build_prompt(facts)

    try:
        if provider == "groq":
            text = _call_groq(prompt)
        elif provider == "google":
            text = _call_google(prompt)
        else:
            raise ValueError(f"Unknown provider: {provider}")

        logger.info("LLM analysis via %s — %d chars", provider, len(text))
        return {"narrative": text, "provider": provider, "success": True}

    except Exception as exc:
        logger.warning("LLM call failed (%s): %s — using fallback", provider, exc)
        return {
            "narrative": _fallback_narrative(facts),
            "provider":  "fallback",
            "success":   False,
            "error":     str(exc),
        }
