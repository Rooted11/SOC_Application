"""
Claude AI Service
=================
Wraps the Anthropic Claude API for on-demand SOC analyst support:
  - Incident analysis / freeform analyst Q&A
  - Executive report generation
  - Smart AI recommendation on incident creation
  - Threat indicator enrichment

Gracefully falls back to template responses when ANTHROPIC_API_KEY is not set,
so the platform remains fully functional without a key.
"""

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MODEL = "claude-opus-4-6"

_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    if not ANTHROPIC_API_KEY:
        return None
    try:
        import anthropic
        _client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        logger.info("Claude AI client initialised (model: %s)", MODEL)
        return _client
    except ImportError:
        logger.warning("anthropic package not installed — install it to enable Claude AI")
        return None
    except Exception as e:
        logger.error("Failed to initialise Claude client: %s", e)
        return None


SOC_SYSTEM_PROMPT = """You are an elite Tier-3 SOC analyst AI assistant embedded in a Security Operations Center platform.
Your role: help analysts investigate incidents, make containment decisions, and communicate findings clearly.

Guidelines:
- Be specific and actionable; avoid vague recommendations
- Reference MITRE ATT&CK technique IDs where relevant (T####)
- Prioritise by urgency (immediate → short-term → long-term)
- Keep responses structured with clear headers when multi-section
- Assume the analyst is experienced — skip basic definitions
- When IOC matches are present, treat them as high-confidence signals
- Never fabricate threat actor names, IOCs, or CVE numbers not in the provided data"""


# ── Public API ────────────────────────────────────────────────────────────────

def analyze_incident(
    incident: Dict[str, Any],
    query: str,
    ioc_details: Optional[List[Dict]] = None,
) -> str:
    """Answer an analyst's freeform question about a specific incident."""
    client = _get_client()
    if not client:
        return _fallback_analysis(incident, query)

    context = _build_incident_context(incident, ioc_details)
    prompt = f"Incident context:\n{context}\n\nAnalyst question: {query}"

    try:
        resp = client.messages.create(
            model=MODEL,
            max_tokens=1500,
            system=SOC_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text
    except Exception as e:
        logger.error("Claude API error in analyze_incident: %s", e)
        return _fallback_analysis(incident, query)


def generate_executive_report(
    incident: Dict[str, Any],
    soc_stats: Optional[Dict] = None,
) -> str:
    """Generate a polished executive-level incident report."""
    client = _get_client()
    if not client:
        return _fallback_executive_report(incident)

    stats_section = ""
    if soc_stats:
        stats_section = (
            f"\n\nBroader SOC Context:\n"
            f"  Total open incidents: {soc_stats.get('open_incidents', 'N/A')}\n"
            f"  Critical open: {soc_stats.get('critical_open', 'N/A')}\n"
            f"  Security posture score: {soc_stats.get('posture_score', 'N/A')}/100"
        )

    actions_taken = ""
    if incident.get("playbook_actions"):
        actions_taken = "\nAutomated Actions Executed:\n" + "\n".join(
            f"  • {a.get('action', 'action')} — {a.get('status', 'completed')}"
            for a in incident["playbook_actions"][:8]
        )

    prompt = f"""Write a professional executive incident report for a CISO and senior leadership.
Format: Executive Summary, Business Impact Assessment, Timeline of Events, Automated Response Actions, Strategic Recommendations.
Tone: authoritative, clear, no excessive jargon. Target length: ~500 words.

Incident Data:
  ID: #{incident.get('id')}
  Title: {incident.get('title')}
  Severity: {str(incident.get('severity', '')).upper()}
  Risk Score: {incident.get('risk_score', 0)}/100
  Status: {incident.get('status')}
  Detected: {incident.get('created_at', 'N/A')}
  Affected Assets: {', '.join(incident.get('affected_assets') or []) or 'Under investigation'}
  Threat Intel Matches: {', '.join(incident.get('ioc_matches') or []) or 'None confirmed'}
  Detection Method: {incident.get('description', 'Automated ML anomaly detection')}{actions_taken}{stats_section}"""

    try:
        resp = client.messages.create(
            model=MODEL,
            max_tokens=1200,
            system=(
                "You are a senior cybersecurity consultant writing executive reports. "
                "Be professional, clear, and concise. Avoid bullet overload — use prose where appropriate."
            ),
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text
    except Exception as e:
        logger.error("Claude API error in generate_executive_report: %s", e)
        return _fallback_executive_report(incident)


def generate_incident_recommendation(
    incident_title: str,
    severity: str,
    risk_score: float,
    ioc_matches: List[Dict],
    explanation: str,
    event_type: str = "",
    affected_assets: Optional[List[str]] = None,
) -> str:
    """Generate AI recommendation when an incident is auto-created."""
    client = _get_client()
    if not client:
        return _fallback_recommendation(
            incident_title, severity, risk_score, ioc_matches, explanation
        )

    ioc_str = ""
    if ioc_matches:
        ioc_str = "\nMatched Threat Intel:\n" + "\n".join(
            f"  • [{m.get('threat_type', '').upper()}] {m.get('value')} "
            f"({m.get('confidence', 0):.0%} conf, {m.get('feed_source', 'unknown')})"
            for m in ioc_matches[:5]
        )

    asset_str = (
        f"\nAffected Assets: {', '.join(affected_assets)}"
        if affected_assets
        else ""
    )

    prompt = f"""A new security incident has been auto-detected. Provide concise, prioritised response guidance.

Incident: {incident_title}
Severity: {severity.upper()} | Risk Score: {risk_score}/100
Event Type: {event_type or 'unknown'}
ML Detection Reason: {explanation}{asset_str}{ioc_str}

Output format:
IMMEDIATE ACTIONS (0–15 min): [numbered list]
CONTAINMENT (15–60 min): [numbered list]
INVESTIGATION STEPS: [numbered list]
ESCALATE IF: [brief criteria]

Be specific. Reference MITRE ATT&CK IDs where applicable."""

    try:
        resp = client.messages.create(
            model=MODEL,
            max_tokens=700,
            system=SOC_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text
    except Exception as e:
        logger.error("Claude API error in generate_incident_recommendation: %s", e)
        return _fallback_recommendation(
            incident_title, severity, risk_score, ioc_matches, explanation
        )


def enrich_threat_indicator(indicator: Dict[str, Any]) -> str:
    """Generate a plain-English threat summary for an IOC."""
    client = _get_client()
    if not client:
        return _fallback_indicator_enrichment(indicator)

    prompt = (
        f"Provide a 2-sentence threat intelligence summary for this IOC:\n"
        f"Type: {indicator.get('ioc_type')}\n"
        f"Value: {indicator.get('value')}\n"
        f"Threat Type: {indicator.get('threat_type')}\n"
        f"Severity: {indicator.get('severity')}\n"
        f"Confidence: {indicator.get('confidence', 0):.0%}\n"
        f"Tags: {', '.join(indicator.get('tags') or [])}\n\n"
        f"Focus on: what this indicator does and the immediate analyst action."
    )

    try:
        resp = client.messages.create(
            model=MODEL,
            max_tokens=150,
            system=SOC_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text
    except Exception as e:
        logger.error("Claude API error in enrich_threat_indicator: %s", e)
        return _fallback_indicator_enrichment(indicator)


# ── Context builder ───────────────────────────────────────────────────────────

def _build_incident_context(
    incident: Dict[str, Any],
    ioc_details: Optional[List[Dict]] = None,
) -> str:
    parts = [
        f"Incident #{incident.get('id')} [{str(incident.get('severity', '')).upper()}]",
        f"Title: {incident.get('title', 'N/A')}",
        f"Risk Score: {incident.get('risk_score', 0)}/100",
        f"Status: {incident.get('status', 'unknown')}",
        f"Description: {incident.get('description', 'N/A')}",
    ]
    if incident.get("affected_assets"):
        parts.append(f"Affected Assets: {', '.join(incident['affected_assets'])}")
    if incident.get("ioc_matches"):
        parts.append(f"IOC Matches: {', '.join(incident['ioc_matches'])}")
    tl = incident.get("trigger_log")
    if tl:
        parts.append(
            f"Trigger Log: {tl.get('event_type')} | "
            f"{tl.get('ip_src')} → {tl.get('ip_dst')} | "
            f"user={tl.get('user')} | {str(tl.get('timestamp', ''))[:19]}"
        )
    if ioc_details:
        for ioc in ioc_details[:3]:
            parts.append(
                f"IOC Detail: [{ioc.get('threat_type', '').upper()}] {ioc.get('value')} "
                f"— {ioc.get('confidence', 0):.0%} confidence ({ioc.get('feed_source')})"
            )
    return "\n".join(parts)


# ── Fallback templates ────────────────────────────────────────────────────────

_FALLBACK_NOTE = "\n\n[Set ANTHROPIC_API_KEY in docker-compose.yml to enable full Claude AI responses]"

_ACTIONS = {
    "critical": [
        "IMMEDIATE: Isolate affected host(s) from network via EDR/NAC.",
        "Revoke all credentials and OAuth tokens for involved accounts.",
        "Page on-call Tier-3 analyst — open P1 bridge call.",
        "Preserve forensic artefacts (memory, disk) before any remediation.",
        "Follow IR runbook SOC-IR-001; consider engaging external IR firm.",
    ],
    "high": [
        "Contain affected host — restrict lateral movement at switch level.",
        "Reset passwords for all involved user accounts.",
        "Alert on-call SOC analyst via PagerDuty.",
        "Collect endpoint telemetry (memory dump + process list).",
        "Escalate if containment not confirmed within 30 minutes.",
    ],
    "medium": [
        "Investigate source IP reputation and user account history.",
        "Review correlated logs for the past 2 hours.",
        "Block source IP at perimeter as a precaution.",
        "Update incident ticket with findings.",
    ],
    "low": [
        "Monitor for recurrence over the next 4 hours.",
        "Verify this is not a false positive via SIEM correlation.",
        "Document findings and close if confirmed benign.",
    ],
}


def _fallback_recommendation(title, severity, risk_score, ioc_matches, explanation) -> str:
    lines = [
        f"AI Analysis — {title}",
        "",
        f"Risk Score: {risk_score}/100 | Severity: {severity.upper()}",
    ]
    if explanation:
        lines.append(f"Detection: {explanation}")
    if ioc_matches:
        lines.append(f"\nThreat Intel: {len(ioc_matches)} IOC(s) correlated.")
        for m in ioc_matches[:3]:
            lines.append(
                f"  • [{m.get('threat_type','').upper()}] {m.get('value')} "
                f"({m.get('confidence',0):.0%})"
            )
    lines.append("\nRecommended Actions:")
    for i, a in enumerate(_ACTIONS.get(severity, _ACTIONS["low"]), 1):
        lines.append(f"{i}. {a}")
    lines.append(_FALLBACK_NOTE)
    return "\n".join(lines)


def _fallback_analysis(incident: Dict, query: str) -> str:
    lq = query.lower()
    if "contain" in lq or "isolat" in lq:
        return _fallback_containment(incident)
    if "root cause" in lq or "why" in lq:
        return _fallback_root_cause(incident)
    if "report" in lq or "executive" in lq:
        return _fallback_executive_report(incident)
    if "mitre" in lq or "ttp" in lq:
        return _fallback_mitre(incident)
    risk = incident.get("risk_score", 0)
    sev  = str(incident.get("severity", "medium")).lower()
    return (
        f"Analysis for Incident #{incident.get('id')} [{sev.upper()}]\n"
        f"Risk: {risk}/100\n\n"
        f"Query: {query}\n\n"
        f"{'CRITICAL: Active, targeted attack — immediate containment required.' if risk >= 80 else 'HIGH confidence of malicious activity — investigate and contain.' if risk >= 60 else 'Elevated risk indicators — investigation warranted.'}\n\n"
        f"Key signals:\n"
        f"• ML risk score: {risk}/100 ({'strong' if risk >= 70 else 'moderate'} outlier vs baseline)\n"
        f"• IOC matches: {len(incident.get('ioc_matches') or [])}\n"
        f"• Description: {incident.get('description','N/A')}"
        + _FALLBACK_NOTE
    )


def _fallback_executive_report(incident: Dict) -> str:
    risk   = incident.get("risk_score", 0)
    impact = (
        "CRITICAL: Potential active breach or ransomware deployment." if risk >= 80
        else "HIGH: Significant risk of data loss or service disruption." if risk >= 60
        else "MODERATE: Contained threat with limited impact if resolved promptly."
    )
    return (
        f"EXECUTIVE INCIDENT REPORT\n{'='*52}\n"
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n\n"
        f"SUMMARY\nIncident #{incident.get('id')} | "
        f"Severity: {str(incident.get('severity','')).upper()} | "
        f"Risk: {risk}/100 | Status: {incident.get('status','unknown')}\n\n"
        f"BUSINESS IMPACT\n{impact}\n"
        f"Affected: {', '.join(incident.get('affected_assets') or ['Under investigation'])}\n\n"
        f"RESPONSE\nAutomated detection and playbook response initiated. SOC analysts notified.\n\n"
        f"RECOMMENDATIONS\n"
        + (
            "• Activate Crisis Management Team\n• Prepare regulator/customer notification if PII involved\n• Engage external IR firm if capacity exceeded"
            if risk >= 80
            else "• Ensure SOC has necessary resources\n• Review cyber insurance coverage\n• Schedule post-incident review within 5 business days"
        )
        + _FALLBACK_NOTE
    )


def _fallback_containment(incident: Dict) -> str:
    host = (incident.get("affected_assets") or ["affected-host"])[0]
    return (
        f"CONTAINMENT PLAN — Incident #{incident.get('id')}\n\n"
        f"IMMEDIATE (0-15 min):\n"
        f"1. Isolate {host} at network switch (VLAN quarantine)\n"
        f"2. Revoke all active sessions for involved accounts\n"
        f"3. Take live memory snapshot before any remediation\n"
        f"4. Notify SOC lead and IR manager\n\n"
        f"SHORT-TERM (15-60 min):\n"
        f"5. Block source IPs at perimeter firewall and WAF\n"
        f"6. Search EDR for lateral movement (past 72h)\n"
        f"7. Review DNS query logs for C2 domains\n"
        f"8. Check email gateway for phishing lures\n\n"
        f"ERADICATION:\n"
        f"9. Re-image host from known-good golden image\n"
        f"10. Rotate ALL potentially-exposed credentials\n"
        f"11. Patch exploited vulnerability before restore"
        + _FALLBACK_NOTE
    )


def _fallback_root_cause(incident: Dict) -> str:
    return (
        f"ROOT CAUSE ANALYSIS — Incident #{incident.get('id')}\n\n"
        f"Observed: {incident.get('title','Unknown')}\n"
        f"Detection: {incident.get('description','Anomaly detected by Isolation Forest ML')}\n\n"
        f"Probable Kill Chain:\n"
        f"  1. Initial Access (T1566/T1190) — External source or credential stuffing\n"
        f"  2. Execution (T1059) — Suspicious script or process execution\n"
        f"  3. Persistence (T1053) — Scheduled task or registry modification\n"
        f"  4. Lateral Movement (T1021) — Cross-subnet traffic detected\n\n"
        f"Forensic Steps:\n"
        f"  1. Collect Windows Event Logs 4624, 4625, 4688, 4698\n"
        f"  2. Review PowerShell ScriptBlock logging (Event ID 4104)\n"
        f"  3. Run YARA scan on affected host\n"
        f"  4. Correlate firewall + proxy logs for same timeframe"
        + _FALLBACK_NOTE
    )


def _fallback_mitre(incident: Dict) -> str:
    risk   = incident.get("risk_score", 50)
    n_ttps = min(3 + int(risk // 25), 7)
    ttps   = [
        ("T1566", "Initial Access",       "Phishing / external source indicator"),
        ("T1059", "Execution",            "Command & Scripting interpreter"),
        ("T1053", "Persistence",          "Scheduled Task/Job"),
        ("T1068", "Privilege Escalation", "Exploitation for privilege escalation"),
        ("T1021", "Lateral Movement",     "Remote Services (RDP/SMB)"),
        ("T1041", "Exfiltration",         "Exfiltration Over C2 Channel"),
        ("T1071", "Command & Control",    "Application Layer Protocol (HTTP/S)"),
    ][:n_ttps]
    lines = "\n".join(
        f"  [{t[0]}] {t[1]:<26} {t[2]}" for t in ttps
    )
    return (
        f"MITRE ATT&CK MAPPING — Incident #{incident.get('id')}\n\n"
        f"Probable TTPs (risk score {risk}/100):\n{lines}\n\n"
        f"Detection Recommendations:\n"
        + "\n".join(f"  • Sigma rule for {t[0]}: search SIEM for {t[2].lower()}" for t in ttps)
        + _FALLBACK_NOTE
    )


def _fallback_indicator_enrichment(indicator: Dict) -> str:
    from .threat_intel import THREAT_TEMPLATES
    behaviors = {
        "malware":    "file encryption and credential stealing",
        "phishing":   "spoofed login pages and email lures",
        "c2":         "HTTP/S beaconing every 30–300 seconds",
        "ransomware": "rapid file enumeration and AES encryption",
        "apt":        "spear-phishing followed by living-off-the-land persistence",
    }
    tt = indicator.get("threat_type", "default")
    tpl = THREAT_TEMPLATES.get(tt, THREAT_TEMPLATES["default"])
    return tpl.format(
        name     = indicator.get("value", "unknown"),
        behavior = behaviors.get(tt, "network scanning and exploitation attempts"),
    )
