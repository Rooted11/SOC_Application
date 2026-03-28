"""
Threat Intelligence Service
===========================
Ingests IOCs from multiple feeds, stores them in the DB, and correlates them
against internal log data. AI/NLP enrichment generates plain-English summaries
analysts can act on immediately.

Feed types supported (all simulated in this prototype):
  - threat_feed_alpha  : IP reputation / known malicious hosts
  - threat_feed_beta   : Domain / URL blocklist
  - threat_feed_gamma  : File hash (malware signatures)
  - misp_feed          : MISP-format event feed
  - isac_feed          : Industry ISAC advisories
"""

import hashlib
import json
import logging
import os
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from .database import Incident, ThreatIndicator

logger = logging.getLogger(__name__)

# Docker: __file__ is /backend/app/services/threat_intel.py -> parents[3] = /
# Local: __file__ is .../ai-soc/backend/app/services/threat_intel.py -> parents[3] = ai-soc/
# Both cases: parents[3] / "data" resolves correctly.
_FEED_DEFAULT = Path(__file__).resolve().parents[3] / "data" / "dummy_threat_feed.json"
FEED_FILE = Path(os.getenv("FEED_FILE_PATH", str(_FEED_DEFAULT)))


# NLP enrichment templates
# In production replace with an LLM call (Claude / OpenAI) for richer summaries.
THREAT_TEMPLATES = {
    "malware": (
        "This indicator is associated with {name} malware. "
        "It has been observed performing {behavior}. "
        "Recommended action: isolate affected host, run full AV scan, "
        "and review process creation logs for the past 24 hours."
    ),
    "phishing": (
        "Phishing infrastructure linked to campaign '{name}'. "
        "Targets credential harvesting via {behavior}. "
        "Recommended action: block domain at email gateway, "
        "notify users who received related emails, reset passwords if clicked."
    ),
    "c2": (
        "Command-and-control server for '{name}' botnet. "
        "Communicates over {behavior}. "
        "Recommended action: block IP/domain at firewall, "
        "search EDR telemetry for DNS queries or outbound connections to this host."
    ),
    "ransomware": (
        "Ransomware family '{name}' IOC. "
        "Known TTPs: {behavior}. "
        "Recommended action: immediately isolate host, "
        "snapshot disks for forensics, do NOT reboot, notify IR team."
    ),
    "apt": (
        "Advanced Persistent Threat group '{name}' indicator. "
        "Observed TTP: {behavior}. "
        "Recommended action: escalate to Tier-3 analyst, "
        "preserve all logs, initiate full incident response procedure."
    ),
    "default": (
        "Malicious indicator associated with {name}. "
        "Behaviour observed: {behavior}. "
        "Recommended action: block indicator and investigate affected assets."
    ),
}


class ThreatIntelService:
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}

    def load_from_file(self, db: Session) -> int:
        """Load IOCs from the bundled dummy feed JSON. Returns count added."""
        if not FEED_FILE.exists():
            logger.warning("Threat feed file not found: %s", FEED_FILE)
            return 0

        with open(FEED_FILE) as fh:
            feed = json.load(fh)

        added = 0
        for entry in feed.get("indicators", []):
            if not db.query(ThreatIndicator).filter_by(value=entry["value"]).first():
                ti = ThreatIndicator(
                    ioc_type=entry.get("ioc_type", "ip"),
                    value=entry["value"],
                    threat_type=entry.get("threat_type", "unknown"),
                    severity=entry.get("severity", "medium"),
                    confidence=entry.get("confidence", 0.7),
                    feed_source=entry.get("feed_source", "dummy_feed"),
                    description=entry.get("description", ""),
                    tags=entry.get("tags", []),
                )
                db.add(ti)
                db.flush()
                self._cache[ti.value] = self._indicator_to_dict(ti)
                added += 1

        db.commit()
        logger.info("Loaded %d threat indicators from feed file", added)
        return added

    def fetch_live_feed(self, db: Session, feed_name: str = "all") -> List[Dict]:
        """
        Simulate fetching a live threat feed.
        In production: call TAXII server, MISP API, or commercial feed API.
        Returns list of newly-added IOC dicts.
        """
        simulated_iocs = self._generate_simulated_iocs(20)
        added = []
        for ioc in simulated_iocs:
            if not db.query(ThreatIndicator).filter_by(value=ioc["value"]).first():
                ti = ThreatIndicator(**ioc)
                db.add(ti)
                db.flush()
                self._cache[ti.value] = self._indicator_to_dict(ti)
                added.append(ioc)
        db.commit()
        logger.info("Fetched %d new IOCs from simulated feed '%s'", len(added), feed_name)
        return added

    @staticmethod
    def _generate_simulated_iocs(count: int) -> List[Dict]:
        """Generate random but realistic-looking IOC records."""
        threat_types = ["malware", "phishing", "c2", "ransomware", "apt"]
        ioc_types = ["ip", "domain", "hash", "url"]
        feeds = ["threat_feed_alpha", "threat_feed_beta", "misp_feed", "isac_feed"]
        iocs = []
        for _ in range(count):
            ioc_type = random.choice(ioc_types)
            threat_type = random.choice(threat_types)
            severity = random.choice(["critical", "high", "medium", "low"])
            confidence = round(random.uniform(0.4, 0.99), 2)

            if ioc_type == "ip":
                value = (
                    f"{random.randint(1,254)}.{random.randint(0,254)}."
                    f"{random.randint(0,254)}.{random.randint(1,254)}"
                )
            elif ioc_type == "domain":
                tlds = [".ru", ".cn", ".tk", ".xyz", ".top"]
                value = (
                    f"malicious-{''.join(random.choices('abcdefghijklmnop', k=6))}"
                    f"{random.choice(tlds)}"
                )
            elif ioc_type == "hash":
                value = hashlib.sha256(str(random.random()).encode()).hexdigest()
            else:
                value = f"http://evil-{''.join(random.choices('abcdefg', k=5))}.xyz/payload"

            iocs.append(
                dict(
                    ioc_type=ioc_type,
                    value=value,
                    threat_type=threat_type,
                    severity=severity,
                    confidence=confidence,
                    feed_source=random.choice(feeds),
                    description=f"Simulated {threat_type} indicator",
                    tags=[threat_type, ioc_type],
                    first_seen=datetime.utcnow() - timedelta(days=random.randint(0, 30)),
                    last_seen=datetime.utcnow(),
                    is_active=True,
                )
            )
        return iocs

    def correlate_log(self, db: Session, log_dict: Dict[str, Any]) -> List[Dict]:
        """
        Check if any fields in a log event match known IOCs.
        Returns list of matched indicator dicts.
        """
        candidates = []
        for field in ("ip_src", "ip_dst", "user"):
            value = log_dict.get(field)
            if value:
                candidates.append(str(value))

        raw = log_dict.get("raw_data") or {}
        for field in ("domain", "url", "file_hash"):
            value = raw.get(field)
            if value:
                candidates.append(str(value))

        matches = []
        for value in candidates:
            if value in self._cache:
                matches.append(dict(self._cache[value]))
                continue

            ti = db.query(ThreatIndicator).filter(
                ThreatIndicator.value == value,
                ThreatIndicator.is_active.is_(True),
            ).first()
            if ti:
                indicator_dict = self._indicator_to_dict(ti)
                self._cache[value] = indicator_dict
                matches.append(indicator_dict)

        return matches

    def correlate_incident(self, db: Session, incident: Incident) -> List[Dict]:
        """Correlate all IOCs linked to an incident's affected assets / logs."""
        matches = []
        if incident.trigger_log:
            log_dict = {
                "ip_src": incident.trigger_log.ip_src,
                "ip_dst": incident.trigger_log.ip_dst,
                "user": incident.trigger_log.user,
                "raw_data": incident.trigger_log.raw_data,
            }
            matches = self.correlate_log(db, log_dict)
        return matches

    def enrich_indicator(self, indicator: Dict[str, Any]) -> str:
        """
        Generate a plain-English threat summary using template-based NLP.
        In production swap this for a Claude/OpenAI API call.
        """
        threat_type = indicator.get("threat_type", "default")
        template = THREAT_TEMPLATES.get(threat_type, THREAT_TEMPLATES["default"])
        behaviors = {
            "malware": "file encryption and credential stealing",
            "phishing": "spoofed login pages and email lures",
            "c2": "HTTP/S beaconing every 30-300 seconds",
            "ransomware": "rapid file enumeration and AES encryption",
            "apt": "spear-phishing followed by living-off-the-land persistence",
            "default": "network scanning and exploitation attempts",
        }
        return template.format(
            name=indicator.get("value", "unknown"),
            behavior=behaviors.get(threat_type, behaviors["default"]),
        )

    def generate_threat_summary(self, db: Session) -> Dict[str, Any]:
        """
        Produce an executive-level threat landscape summary.
        Aggregates active IOC counts by type/severity and generates narrative.
        """
        indicators = db.query(ThreatIndicator).filter_by(is_active=True).all()
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_type: Dict[str, int] = {}
        for indicator in indicators:
            by_severity[indicator.severity] = by_severity.get(indicator.severity, 0) + 1
            by_type[indicator.threat_type] = by_type.get(indicator.threat_type, 0) + 1

        top_threat = max(by_type, key=by_type.get) if by_type else "none"
        narrative = (
            f"Threat landscape: {len(indicators)} active IOCs across "
            f"{len(by_type)} threat categories. "
            f"Top threat type: {top_threat} ({by_type.get(top_threat, 0)} IOCs). "
            f"Critical/High IOCs requiring immediate action: "
            f"{by_severity['critical'] + by_severity['high']}."
        )
        return {
            "total_iocs": len(indicators),
            "by_severity": by_severity,
            "by_threat_type": by_type,
            "narrative": narrative,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def generate_ai_recommendation(
        self,
        incident_title: str,
        severity: str,
        risk_score: float,
        ioc_matches: List[Dict],
        explanation: str,
    ) -> str:
        """
        Rule-based AI recommendation for analysts.
        Produce prioritised, actionable guidance based on incident context.
        """
        lines = [f"AI Analysis - {incident_title}", ""]

        lines.append(f"Risk Score: {risk_score}/100 | Severity: {severity.upper()}")
        if explanation:
            lines.append(f"Detection reason: {explanation}")
        lines.append("")

        if ioc_matches:
            lines.append(f"Threat Intel Match: {len(ioc_matches)} known IOC(s) correlated.")
            for match in ioc_matches[:3]:
                lines.append(
                    f"  - [{match['threat_type'].upper()}] {match['value']} "
                    f"(confidence: {match['confidence']:.0%}) - {match['feed_source']}"
                )
            lines.append("")

        actions = {
            "critical": [
                "1. IMMEDIATE: Isolate affected host(s) from network.",
                "2. Revoke all credentials associated with the incident.",
                "3. Page on-call Tier-3 analyst and IR manager.",
                "4. Preserve forensic artefacts before any remediation.",
                "5. Open a P1 bridge call and follow IR runbook SOC-IR-001.",
            ],
            "high": [
                "1. Contain affected host - restrict lateral movement.",
                "2. Reset passwords for involved user accounts.",
                "3. Alert on-call SOC analyst via PagerDuty.",
                "4. Collect endpoint telemetry (memory + process list).",
                "5. Escalate if containment not confirmed in 30 minutes.",
            ],
            "medium": [
                "1. Investigate source IP and user account history.",
                "2. Review related logs for the past 2 hours.",
                "3. Check threat intel for IOC context (see above).",
                "4. Consider blocking the source IP as a precaution.",
                "5. Update incident ticket with findings.",
            ],
            "low": [
                "1. Monitor for recurrence over the next 4 hours.",
                "2. Verify the event is not a false positive.",
                "3. Document findings and close if benign.",
            ],
        }
        severity_key = severity if severity in actions else "low"
        lines.append("Recommended Actions:")
        lines.extend(actions[severity_key])

        return "\n".join(lines)

    @staticmethod
    def _indicator_to_dict(ti: ThreatIndicator) -> Dict[str, Any]:
        return {
            "id": ti.id,
            "ioc_type": ti.ioc_type,
            "value": ti.value,
            "threat_type": ti.threat_type,
            "severity": ti.severity,
            "confidence": ti.confidence,
            "feed_source": ti.feed_source,
            "description": ti.description,
            "tags": ti.tags or [],
        }


threat_intel = ThreatIntelService()
