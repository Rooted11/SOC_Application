import logging
import os
import pwd
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from .database import Alert, Asset, Incident, PlaybookAction, PlaybookStatusEnum

logger = logging.getLogger(__name__)

FORENSICS_DIR = Path("/opt/soc/forensics")
FORENSICS_DIR.mkdir(parents=True, exist_ok=True)


class PlaybookExecutor:
    def _run_cmd(self, cmd: List[str], timeout: int = 20) -> Tuple[bool, str]:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
            output = output.strip()
            if proc.returncode == 0:
                return True, output or "command succeeded"
            return False, output or f"command failed with rc={proc.returncode}"
        except Exception as e:
            logger.exception("Command failed: %s", cmd)
            return False, str(e)

    def _safe_ip(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _safe_username(self, username: str) -> bool:
        if not username:
            return False
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        return all(ch in allowed for ch in username)

    def _do_isolate_host(self, hostname: str, ip: str) -> Tuple[bool, str]:
        """
        Lab isolation: block the source IP on the SOC host.
        """
        if not self._safe_ip(ip):
            return False, f"invalid IP: {ip}"

        ok, msg = self._do_block_ip(ip)
        if ok:
            return True, f"Containment applied for host={hostname}, ip={ip}. {msg}"
        return False, f"Containment failed for host={hostname}, ip={ip}. {msg}"

    def _do_revoke_credentials(self, username: str) -> Tuple[bool, str]:
        """
        Locks a local Linux account.
        """
        if not self._safe_username(username):
            return False, f"invalid username: {username}"

        try:
            pwd.getpwnam(username)
        except KeyError:
            return False, f"user '{username}' does not exist locally"

        ok, msg = self._run_cmd(["sudo", "usermod", "-L", username])
        if ok:
            return True, f"local account '{username}' locked"
        return False, f"failed to lock '{username}': {msg}"

    def _do_block_ip(self, ip: str) -> Tuple[bool, str]:
        if not self._safe_ip(ip):
            return False, f"invalid IP: {ip}"

        if shutil_which("ufw"):
            check_ok, _ = self._run_cmd(["sudo", "ufw", "status"])
            if check_ok:
                ok, msg = self._run_cmd(["sudo", "ufw", "deny", "from", ip])
                if ok:
                    return True, f"ufw deny from {ip}: {msg}"

        if shutil_which("iptables"):
            exists_ok, _ = self._run_cmd(["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
            if exists_ok:
                return True, f"iptables rule already present for {ip}"

            ok, msg = self._run_cmd(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            if ok:
                return True, f"iptables drop added for {ip}"
            return False, f"iptables block failed for {ip}: {msg}"

        return False, "neither ufw nor iptables is available"

    def _do_collect_forensics(self, hostname: str) -> Tuple[bool, str]:
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        outdir = FORENSICS_DIR / f"{hostname}_{timestamp}"
        outdir.mkdir(parents=True, exist_ok=True)

        commands = {
            "ip_addr.txt": ["ip", "addr"],
            "ss_tulpn.txt": ["ss", "-tulpn"],
            "ps_aux.txt": ["ps", "aux"],
            "last_logins.txt": ["last", "-n", "20"],
            "journal_tail.txt": ["journalctl", "-n", "200", "--no-pager"],
        }

        results = []
        for filename, cmd in commands.items():
            ok, msg = self._run_cmd(cmd, timeout=30)
            target = outdir / filename
            target.write_text(msg if msg else "", encoding="utf-8")
            results.append(f"{filename}: {'ok' if ok else 'failed'}")

        return True, f"forensics written to {outdir} | " + ", ".join(results)

    def _do_send_alert(
        self,
        incident: Incident,
        channel: str,
        recipient: str,
    ) -> Tuple[bool, str]:
        message = (
            f"[{str(incident.severity).upper()}] Incident #{incident.id}: {incident.title}\n"
            f"Risk: {incident.risk_score}/100 | Status: {incident.status}\n"
            f"Assets: {', '.join(incident.affected_assets or [])}\n"
            f"http://localhost:3000/incidents/{incident.id}"
        )

        alert_dir = Path("/opt/soc/alerts")
        alert_dir.mkdir(parents=True, exist_ok=True)
        alert_file = alert_dir / f"incident_{incident.id}.log"
        with alert_file.open("a", encoding="utf-8") as f:
            f.write(
                f"{datetime.utcnow().isoformat()}Z | channel={channel} | recipient={recipient}\n"
                f"{message}\n\n"
            )

        logger.warning("[PLAYBOOK ALERT] %s -> %s | incident=%s", channel, recipient, incident.id)
        return True, message

    def _log_action(
        self,
        db: Session,
        incident_id: int,
        playbook: str,
        action: str,
        target: str,
        ok: bool,
        result: str,
    ) -> PlaybookAction:
        pa = PlaybookAction(
            incident_id=incident_id,
            playbook=playbook,
            action=action,
            target=target,
            status=PlaybookStatusEnum.completed if ok else PlaybookStatusEnum.failed,
            result=result,
            executed_at=datetime.utcnow(),
        )
        db.add(pa)
        db.commit()
        db.refresh(pa)
        return pa

    def _log_alert(
        self,
        db: Session,
        incident: Incident,
        channel: str,
        recipient: str,
        message: str,
    ):
        db.add(
            Alert(
                incident_id=incident.id,
                channel=channel,
                recipient=recipient,
                message=message,
                sent_at=datetime.utcnow(),
                delivered=True,
            )
        )
        db.commit()

    def run_isolate_host(
        self,
        db: Session,
        incident: Incident,
        hostname: str,
        ip: str,
    ) -> List[PlaybookAction]:
        actions = []

        ok, msg = self._do_isolate_host(hostname, ip)
        actions.append(
            self._log_action(
                db,
                incident.id,
                "isolate_host",
                "contain_source_ip",
                ip,
                ok,
                msg,
            )
        )

        asset = db.query(Asset).filter(Asset.hostname == hostname).first()
        if asset:
            asset.is_isolated = ok
            db.commit()

        ok2, msg2 = self._do_send_alert(incident, "local", "soc-oncall")
        self._log_alert(db, incident, "local", "soc-oncall", msg2)
        actions.append(
            self._log_action(
                db,
                incident.id,
                "isolate_host",
                "notify_analyst",
                "soc-oncall",
                ok2,
                msg2,
            )
        )
        return actions

    def run_revoke_credentials(
        self,
        db: Session,
        incident: Incident,
        username: str,
    ) -> List[PlaybookAction]:
        actions = []

        ok, msg = self._do_revoke_credentials(username)
        actions.append(
            self._log_action(
                db,
                incident.id,
                "revoke_credentials",
                "lock_local_account",
                username,
                ok,
                msg,
            )
        )

        ok2, msg2 = self._do_send_alert(incident, "local", f"manager:{username}")
        self._log_alert(db, incident, "local", f"manager:{username}", msg2)
        actions.append(
            self._log_action(
                db,
                incident.id,
                "revoke_credentials",
                "notify_manager",
                f"manager:{username}",
                ok2,
                msg2,
            )
        )
        return actions

    def run_block_ip(
        self,
        db: Session,
        incident: Incident,
        ip: str,
    ) -> List[PlaybookAction]:
        ok, msg = self._do_block_ip(ip)
        return [
            self._log_action(
                db,
                incident.id,
                "block_ip",
                "host_firewall_block",
                ip,
                ok,
                msg,
            )
        ]

    def run_send_alert(
        self,
        db: Session,
        incident: Incident,
        channels: Optional[List[str]] = None,
    ) -> List[PlaybookAction]:
        channels = channels or ["local"]
        actions = []

        for ch in channels:
            ok, msg = self._do_send_alert(incident, ch, "soc-team")
            self._log_alert(db, incident, ch, "soc-team", msg)
            actions.append(
                self._log_action(
                    db,
                    incident.id,
                    "send_alert",
                    f"dispatch_{ch}",
                    "soc-team",
                    ok,
                    msg,
                )
            )
        return actions

    def run_full_response(
        self,
        db: Session,
        incident: Incident,
        hostname: str,
        ip: str,
        username: str,
    ) -> List[PlaybookAction]:
        actions = []
        actions += self.run_isolate_host(db, incident, hostname, ip)
        actions += self.run_revoke_credentials(db, incident, username)
        actions += self.run_block_ip(db, incident, ip)

        ok, msg = self._do_collect_forensics(hostname)
        actions.append(
            self._log_action(
                db,
                incident.id,
                "full_response",
                "forensic_collection",
                hostname,
                ok,
                msg,
            )
        )

        actions += self.run_send_alert(db, incident, ["local"])
        return actions

    def execute_for_incident(
        self,
        db: Session,
        incident: Incident,
        override_playbook: Optional[str] = None,
    ) -> List[PlaybookAction]:
        assets = incident.affected_assets or ["unknown-host"]
        hostname = assets[0]
        ip = getattr(incident.trigger_log, "ip_src", None) or "0.0.0.0"
        user = getattr(incident.trigger_log, "user", None) or "unknown"
        event = getattr(incident.trigger_log, "event_type", None) or ""

        sev = (
            incident.severity.value
            if hasattr(incident.severity, "value")
            else str(incident.severity)
        )

        playbook = override_playbook or self._select_playbook(sev, event)
        logger.info(
            "Executing playbook '%s' for incident #%d (sev=%s)",
            playbook,
            incident.id,
            sev,
        )

        dispatch: Dict[str, callable] = {
            "isolate_host": lambda: self.run_isolate_host(db, incident, hostname, ip),
            "revoke_credentials": lambda: self.run_revoke_credentials(db, incident, user),
            "block_ip": lambda: self.run_block_ip(db, incident, ip),
            "send_alert": lambda: self.run_send_alert(db, incident),
            "full_response": lambda: self.run_full_response(db, incident, hostname, ip, user),
        }

        return dispatch.get(playbook, dispatch["send_alert"])()

    @staticmethod
    def _select_playbook(severity: str, event_type: str) -> str:
        if severity == "critical":
            return "full_response"
        if event_type in ("lateral_movement", "malware_detected", "c2_beacon", "port_scan"):
            return "block_ip"
        if event_type in ("privilege_escalation", "auth_failure"):
            return "revoke_credentials"
        if severity == "high":
            return "block_ip"
        return "send_alert"


def shutil_which(binary: str) -> Optional[str]:
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(path) / binary
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


executor = PlaybookExecutor()
