"""
Automated Playbook Execution Service
=====================================
Playbooks are ordered sequences of response actions executed automatically
when an incident crosses a severity threshold.

Available playbooks
-------------------
  isolate_host       — quarantine the affected host via EDR/NAC API
  revoke_credentials — disable AD/IdP account and revoke OAuth tokens
  block_ip           — push IP to perimeter firewall deny-list
  send_alert         — dispatch structured alert to analyst channels
  collect_forensics  — trigger memory/disk snapshot on affected host
  full_response      — compound: isolate + revoke + block + forensics + alert

All infrastructure calls are SIMULATED in this prototype.
Replace the _do_* stubs with real vendor API calls.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from .database import Alert, Asset, Incident, PlaybookAction, PlaybookStatusEnum

logger = logging.getLogger(__name__)


class PlaybookExecutor:

    # ── Simulated infrastructure actions ────────────────────────────────────

    def _do_isolate_host(self, hostname: str, ip: str) -> Tuple[bool, str]:
        """
        Simulates sending a quarantine command to an EDR platform.
        Real: CrowdStrike RTR  POST /real-time-response/entities/active-sessions/v1
              Cisco ISE        PUT  /api/v1/policy/network-access/identities/...
        """
        logger.info("[PLAYBOOK] ISOLATE HOST %s (%s)", hostname, ip)
        return True, f"Host {hostname} ({ip}) quarantine command sent via EDR API"

    def _do_revoke_credentials(self, username: str) -> Tuple[bool, str]:
        """
        Simulates disabling an AD/Okta account and revoking OAuth tokens.
        Real: AD   — Set-ADUser -Identity $user -Enabled $false
              Okta — POST /api/v1/users/{id}/lifecycle/deactivate
              AWS  — iam.disable_login_profile(UserName=username)
        """
        logger.info("[PLAYBOOK] REVOKE CREDENTIALS for '%s'", username)
        return True, f"Account '{username}' disabled in AD; OAuth tokens revoked"

    def _do_block_ip(self, ip: str) -> Tuple[bool, str]:
        """
        Simulates adding an IP to the perimeter firewall deny-list.
        Real: Palo Alto — POST /restapi/v10.1/Policies/SecurityRules
              AWS WAF   — update_ip_set()
        """
        logger.info("[PLAYBOOK] BLOCK IP %s", ip)
        return True, f"IP {ip} added to firewall deny-list (simulated)"

    def _do_collect_forensics(self, hostname: str) -> Tuple[bool, str]:
        """
        Simulates triggering a forensic memory/disk snapshot.
        Real: Velociraptor — POST /api/v1/CreateHunt (artifact: Windows.Memory.Acquisition)
              EDR live-response memory dump
        """
        logger.info("[PLAYBOOK] COLLECT FORENSICS on %s", hostname)
        return True, f"Forensic snapshot triggered on {hostname} (simulated)"

    def _do_send_alert(
        self,
        incident: Incident,
        channel: str,
        recipient: str,
    ) -> Tuple[bool, str]:
        """
        Simulates dispatching a structured alert.
        Real: Slack     — POST https://hooks.slack.com/services/...
              PagerDuty — POST https://events.pagerduty.com/v2/enqueue
              Email     — boto3 SES / SMTP
        """
        message = (
            f"[{str(incident.severity).upper()}] Incident #{incident.id}: {incident.title}\n"
            f"Risk: {incident.risk_score}/100 | Status: {incident.status}\n"
            f"Assets: {', '.join(incident.affected_assets or [])}\n"
            f"http://localhost:3000/incidents/{incident.id}"
        )
        logger.info("[PLAYBOOK] ALERT → %s/%s", channel, recipient)
        return True, message

    # ── DB helpers ───────────────────────────────────────────────────────────

    def _log_action(
        self, db: Session, incident_id: int, playbook: str,
        action: str, target: str, ok: bool, result: str,
    ) -> PlaybookAction:
        pa = PlaybookAction(
            incident_id = incident_id,
            playbook    = playbook,
            action      = action,
            target      = target,
            status      = PlaybookStatusEnum.completed if ok else PlaybookStatusEnum.failed,
            result      = result,
            executed_at = datetime.utcnow(),
        )
        db.add(pa)
        db.commit()
        db.refresh(pa)
        return pa

    def _log_alert(
        self, db: Session, incident: Incident,
        channel: str, recipient: str, message: str,
    ):
        db.add(Alert(
            incident_id = incident.id,
            channel     = channel,
            recipient   = recipient,
            message     = message,
            sent_at     = datetime.utcnow(),
            delivered   = True,
        ))
        db.commit()

    # ── Individual playbooks ─────────────────────────────────────────────────

    def run_isolate_host(
        self, db: Session, incident: Incident, hostname: str, ip: str
    ) -> List[PlaybookAction]:
        actions = []
        ok, msg = self._do_isolate_host(hostname, ip)
        actions.append(self._log_action(db, incident.id, "isolate_host",
                                        "edr_quarantine", hostname, ok, msg))
        asset = db.query(Asset).filter(Asset.hostname == hostname).first()
        if asset:
            asset.is_isolated = True
            db.commit()
        ok2, msg2 = self._do_send_alert(incident, "slack", "soc-oncall")
        self._log_alert(db, incident, "slack", "soc-oncall",
                        f"Host {hostname} isolated. {msg}")
        actions.append(self._log_action(db, incident.id, "isolate_host",
                                        "notify_analyst", "soc-oncall", ok2, msg2))
        return actions

    def run_revoke_credentials(
        self, db: Session, incident: Incident, username: str
    ) -> List[PlaybookAction]:
        actions = []
        ok, msg = self._do_revoke_credentials(username)
        actions.append(self._log_action(db, incident.id, "revoke_credentials",
                                        "disable_account", username, ok, msg))
        ok2, msg2 = self._do_send_alert(incident, "email", f"manager:{username}")
        self._log_alert(db, incident, "email", f"manager:{username}", msg2)
        actions.append(self._log_action(db, incident.id, "revoke_credentials",
                                        "notify_manager", f"manager:{username}", ok2, msg2))
        return actions

    def run_block_ip(
        self, db: Session, incident: Incident, ip: str
    ) -> List[PlaybookAction]:
        ok, msg = self._do_block_ip(ip)
        return [self._log_action(db, incident.id, "block_ip",
                                 "firewall_block", ip, ok, msg)]

    def run_send_alert(
        self,
        db: Session,
        incident: Incident,
        channels: Optional[List[str]] = None,
    ) -> List[PlaybookAction]:
        channels = channels or ["slack", "email", "pagerduty"]
        actions  = []
        for ch in channels:
            ok, msg = self._do_send_alert(incident, ch, "soc-team")
            self._log_alert(db, incident, ch, "soc-team", msg)
            actions.append(self._log_action(db, incident.id, "send_alert",
                                            f"dispatch_{ch}", "soc-team", ok, msg))
        return actions

    def run_full_response(
        self, db: Session, incident: Incident,
        hostname: str, ip: str, username: str,
    ) -> List[PlaybookAction]:
        """
        Critical-severity compound playbook:
          1. Isolate host
          2. Revoke credentials
          3. Block source IP
          4. Collect forensics
          5. Alert all channels
        """
        actions = []
        actions += self.run_isolate_host(db, incident, hostname, ip)
        actions += self.run_revoke_credentials(db, incident, username)
        actions += self.run_block_ip(db, incident, ip)
        ok, msg = self._do_collect_forensics(hostname)
        actions.append(self._log_action(db, incident.id, "full_response",
                                        "forensic_collection", hostname, ok, msg))
        actions += self.run_send_alert(db, incident, ["slack", "email", "pagerduty"])
        return actions

    # ── Auto-selector ────────────────────────────────────────────────────────

    def execute_for_incident(
        self,
        db: Session,
        incident: Incident,
        override_playbook: Optional[str] = None,
    ) -> List[PlaybookAction]:
        """
        Auto-select the appropriate playbook based on severity and event type,
        then execute it.  Analysts can override via the API.
        """
        assets   = incident.affected_assets or ["unknown-host"]
        hostname = assets[0]
        ip       = getattr(incident.trigger_log, "ip_src",    None) or "0.0.0.0"
        user     = getattr(incident.trigger_log, "user",      None) or "unknown"
        event    = getattr(incident.trigger_log, "event_type",None) or ""
        sev      = (incident.severity.value
                    if hasattr(incident.severity, "value") else str(incident.severity))

        playbook = override_playbook or self._select_playbook(sev, event)
        logger.info("Executing playbook '%s' for incident #%d (sev=%s)",
                    playbook, incident.id, sev)

        dispatch: Dict = {
            "isolate_host":       lambda: self.run_isolate_host(db, incident, hostname, ip),
            "revoke_credentials": lambda: self.run_revoke_credentials(db, incident, user),
            "block_ip":           lambda: self.run_block_ip(db, incident, ip),
            "send_alert":         lambda: self.run_send_alert(db, incident),
            "full_response":      lambda: self.run_full_response(
                                      db, incident, hostname, ip, user),
        }
        return dispatch.get(playbook, dispatch["send_alert"])()

    @staticmethod
    def _select_playbook(severity: str, event_type: str) -> str:
        if severity == "critical":
            return "full_response"
        if event_type in ("lateral_movement", "malware_detected", "c2_beacon"):
            return "isolate_host"
        if event_type in ("privilege_escalation", "auth_failure"):
            return "revoke_credentials"
        if severity == "high":
            return "send_alert"
        return "send_alert"


# Module-level singleton
executor = PlaybookExecutor()
