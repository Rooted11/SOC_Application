#!/usr/bin/env python3
"""
soc_manage.py -- Ataraxia SOC Remote Management Tool
=====================================================
Run from your Windows machine to manage the SOC without SSH.
Talks directly to the backend API at http://<SOC_UBUNTU_IP>:8000.

NOTE: Forces UTF-8 stdout on Windows to handle Unicode from the backend.

Usage:
  python scripts/soc_manage.py status          # Full SOC health check
  python scripts/soc_manage.py incidents        # List all incidents
  python scripts/soc_manage.py incidents --open # Only open incidents
  python scripts/soc_manage.py logs             # Recent log stats
  python scripts/soc_manage.py logs --inject    # Inject test logs
  python scripts/soc_manage.py alarms           # List all alarms
  python scripts/soc_manage.py alarms --create "message" --severity critical
  python scripts/soc_manage.py playbooks        # List playbooks
  python scripts/soc_manage.py detections       # List detection rules
  python scripts/soc_manage.py services         # Check Docker services (requires SSH)
  python scripts/soc_manage.py restart          # Restart all containers (requires SSH)
  python scripts/soc_manage.py agent-status     # Check soc-agent systemd status (requires SSH)
  python scripts/soc_manage.py seed             # Re-run attack simulation
  python scripts/soc_manage.py resolve-all      # Resolve all open incidents
"""

import argparse
import io
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

# Force UTF-8 output on Windows to handle Unicode from the backend
if sys.platform == "win32" and not os.environ.get("PYTHONIOENCODING"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# -- Configuration -------------------------------------------------------------
API_BASE = os.getenv("SOC_API_URL", "http://<SOC_UBUNTU_IP>:8000")
VM_HOST = os.getenv("SOC_VM_HOST", "<SOC_UBUNTU_IP>")
VM_USER = os.getenv("SOC_VM_USER", "your-vm-user")
VM_PASS = os.getenv("SOC_VM_PASS", "your-vm-password")
AUTH_USER = os.getenv("SOC_AUTH_USER", "soc_operator")
AUTH_PASS = os.getenv("SOC_AUTH_PASS", "change-me-locally")
AGENT_TOKEN = os.getenv("SOC_AGENT_TOKEN", "lab-ingest-token")

# -- Colors --------------------------------------------------------------------
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

SEV_COLOR = {
    "critical": C.RED,
    "high": C.MAGENTA,
    "medium": C.YELLOW,
    "low": C.CYAN,
    "info": C.DIM,
}

STATUS_ICON = {
    "open": f"{C.RED}*{C.RESET}",
    "investigating": f"{C.YELLOW}~{C.RESET}",
    "contained": f"{C.BLUE}={C.RESET}",
    "resolved": f"{C.GREEN}+{C.RESET}",
}

# -- API Helpers ---------------------------------------------------------------
_token_cache = None

def get_token():
    global _token_cache
    if _token_cache:
        return _token_cache
    data = json.dumps({"username": AUTH_USER, "password": AUTH_PASS}).encode()
    req = urllib_request.Request(
        f"{API_BASE}/api/auth/login", data=data,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib_request.urlopen(req, timeout=10) as resp:
            _token_cache = json.loads(resp.read())["access_token"]
            return _token_cache
    except Exception as e:
        print(f"{C.RED}Auth failed: {e}{C.RESET}")
        sys.exit(1)

def api(method, path, body=None, use_agent_token=False):
    headers = {"Content-Type": "application/json"}
    if use_agent_token:
        headers["X-Agent-Token"] = AGENT_TOKEN
        headers["Authorization"] = f"Bearer {AGENT_TOKEN}"
    else:
        headers["Authorization"] = f"Bearer {get_token()}"
    data = json.dumps(body).encode() if body else None
    req = urllib_request.Request(f"{API_BASE}{path}", data=data, headers=headers, method=method)
    try:
        with urllib_request.urlopen(req, timeout=15) as resp:
            if resp.status == 204:
                return None
            return json.loads(resp.read())
    except HTTPError as e:
        err = e.read().decode(errors="ignore")
        print(f"{C.RED}HTTP {e.code}: {err[:300]}{C.RESET}")
        return None
    except URLError as e:
        print(f"{C.RED}Connection failed: {e}{C.RESET}")
        print(f"{C.DIM}Is the VM running at {API_BASE}?{C.RESET}")
        return None

def ssh_cmd(cmd):
    """Run a command on the VM via SSH through WSL."""
    full = (
        f'wsl -d kali-linux -- bash -c "'
        f"sshpass -p '{VM_PASS}' ssh -T -o StrictHostKeyChecking=no "
        f"{VM_USER}@{VM_HOST} '{cmd}'\""
    )
    try:
        result = subprocess.run(full, capture_output=True, text=True, shell=True, timeout=30)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return f"{C.RED}SSH command timed out{C.RESET}"
    except Exception as e:
        return f"{C.RED}SSH failed: {e}{C.RESET}"

# -- Commands ------------------------------------------------------------------

def cmd_status(args):
    """Full SOC health dashboard."""
    print(f"\n{C.BOLD}{C.CYAN}{'=' * 60}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  Ataraxia SOC -- System Status{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'=' * 60}{C.RESET}\n")

    # Health check
    health = api("GET", "/api/system/health")
    if health:
        print(f"  {C.GREEN}Backend:{C.RESET}    ONLINE")
        for k, v in health.items():
            if k != "status":
                print(f"  {C.DIM}{k}:{C.RESET}  {v}")
    else:
        print(f"  {C.RED}Backend:    OFFLINE{C.RESET}")
        return

    # Overview
    overview = api("GET", "/api/overview")
    if overview:
        h = overview.get("headline", {})
        r = overview.get("response", {})
        a = overview.get("assets", {})
        i = overview.get("intel", {})

        print(f"\n  {C.BOLD}--- Dashboard ---{C.RESET}")
        score = h.get("posture_score", 0)
        score_color = C.GREEN if score >= 70 else C.YELLOW if score >= 40 else C.RED
        print(f"  Posture Score:     {score_color}{score}/100{C.RESET}")
        print(f"  Open Incidents:    {C.YELLOW}{h.get('open_incidents', 0)}{C.RESET} ({C.RED}{h.get('critical_open', 0)} critical{C.RESET}, {C.MAGENTA}{h.get('high_open', 0)} high{C.RESET})")
        print(f"  Logs (24h):        {h.get('recent_logs_24h', 0)} ({h.get('recent_anomalies_24h', 0)} anomalous)")
        print(f"  Containment Rate:  {r.get('containment_rate_pct', 0):.0f}%")
        print(f"  Automation Rate:   {r.get('automation_rate_pct', 0):.0f}%")
        print(f"  Assets:            {a.get('total', 0)} total, {a.get('critical', 0)} critical")
        print(f"  Threat Intel IOCs: {i.get('active_iocs', 0)} ({i.get('critical_iocs', 0)} critical)")

        tops = overview.get("top_event_types", [])
        if tops:
            print(f"\n  {C.BOLD}--- Top Event Types ---{C.RESET}")
            for t in tops[:5]:
                bar = "#" * min(t["count"] // 5, 40)
                print(f"  {t['event_type']:>25}  {bar} {t['count']}")

    # Playbooks
    pbs = api("GET", "/api/config/playbooks") or []
    print(f"\n  {C.BOLD}--- Playbooks ({len(pbs)}) ---{C.RESET}")
    for p in pbs:
        status = f"{C.GREEN}ON{C.RESET}" if p.get("enabled") else f"{C.RED}OFF{C.RESET}"
        print(f"  [{status}] {p['name']}")

    # Alarms
    alarms = api("GET", "/api/alarms") or []
    unacked = [a for a in alarms if a.get("status") != "acknowledged"]
    print(f"\n  {C.BOLD}--- Alarms ({len(alarms)} total, {len(unacked)} unacknowledged) ---{C.RESET}")
    for a in alarms[-5:]:
        sev = a.get("severity", "info")
        color = SEV_COLOR.get(sev, "")
        ack = f"{C.GREEN}ACK{C.RESET}" if a.get("status") == "acknowledged" else f"{C.RED}NEW{C.RESET}"
        print(f"  [{ack}] {color}[{sev.upper():>8}]{C.RESET} {a['message'][:65]}")

    print(f"\n{C.BOLD}{C.CYAN}{'=' * 60}{C.RESET}\n")


def cmd_incidents(args):
    """List incidents."""
    params = {}
    if args.open:
        params["status"] = "open"
    if args.severity:
        params["severity"] = args.severity

    path = "/api/incidents?" + "&".join(f"{k}={v}" for k, v in params.items()) if params else "/api/incidents"
    raw = api("GET", path)
    if not raw:
        print(f"{C.DIM}No incidents found.{C.RESET}")
        return

    # Handle both list and paginated dict responses
    if isinstance(raw, dict):
        incidents = raw.get("incidents", [])
        total = raw.get("total", len(incidents))
    else:
        incidents = raw
        total = len(raw)

    print(f"\n{C.BOLD}Incidents ({total} total){C.RESET}\n")
    print(f"  {'ID':>4}  {'Status':>13}  {'Severity':>10}  {'Risk':>5}  Title")
    print(f"  {'-' * 4}  {'-' * 13}  {'-' * 10}  {'-' * 5}  {'-' * 40}")

    for inc in incidents[:30]:
        sev = inc.get("severity", "info")
        status = inc.get("status", "?")
        icon = STATUS_ICON.get(status, "o")
        color = SEV_COLOR.get(sev, "")
        risk = inc.get("risk_score", 0)
        title = inc.get("title", "?")[:55]
        print(f"  {inc['id']:>4}  {icon} {status:>11}  {color}{sev.upper():>10}{C.RESET}  {risk:>5.1f}  {title}")

    print()


def cmd_logs(args):
    """Log stats or inject test logs."""
    if args.inject:
        import random
        now = datetime.now(timezone.utc)
        logs = []
        for i in range(10):
            logs.append({
                "source": "test",
                "timestamp": now.isoformat(),
                "log_level": "info",
                "message": f"Test log entry #{i+1} from soc_manage.py at {now.isoformat()}",
                "ip_src": "<VM_HOST_IP>",
                "event_type": "syslog",
                "user": "test_user",
                "raw_data": {"host": "windows-host", "tool": "soc_manage.py"},
            })
        result = api("POST", "/api/logs/ingest", body={"logs": logs}, use_agent_token=True)
        if result:
            print(f"{C.GREEN}Injected {result.get('ingested', result.get('enqueued', 10))} test logs{C.RESET}")
        return

    stats = api("GET", "/api/logs/stats")
    if stats:
        print(f"\n{C.BOLD}Log Statistics{C.RESET}\n")
        print(f"  Total Logs:     {stats.get('total_logs', 0)}")
        print(f"  Anomalous:      {stats.get('anomalous_logs', 0)} ({stats.get('anomaly_rate_pct', 0):.1f}%)")
        print(f"  Avg Risk Score: {stats.get('avg_risk_score', 0):.1f}")
        by_source = stats.get("by_source", {})
        if by_source:
            print(f"\n  {C.BOLD}By Source:{C.RESET}")
            for src, count in sorted(by_source.items(), key=lambda x: -x[1]):
                bar = "#" * min(count // 3, 40)
                print(f"    {src:>15}  {bar} {count}")
        print()


def cmd_alarms(args):
    """List or create alarms."""
    if args.create:
        result = api("POST", "/api/alarms", body={
            "source": args.source or "Manual",
            "message": args.create,
            "severity": args.severity or "medium",
        })
        if result:
            print(f"{C.GREEN}Alarm created (id={result.get('id')}){C.RESET}")
        return

    if args.ack:
        result = api("POST", f"/api/alarms/{args.ack}/ack")
        if result:
            print(f"{C.GREEN}Alarm {args.ack} acknowledged{C.RESET}")
        return

    alarms = api("GET", "/api/alarms") or []
    print(f"\n{C.BOLD}Alarms ({len(alarms)}){C.RESET}\n")
    for a in alarms:
        sev = a.get("severity", "info")
        color = SEV_COLOR.get(sev, "")
        ack = f"{C.GREEN}ACK{C.RESET}" if a.get("status") == "acknowledged" else f"{C.RED}NEW{C.RESET}"
        print(f"  #{a['id']:>3} [{ack}] {color}[{sev.upper():>8}]{C.RESET} {a.get('source', '?'):>18} | {a['message'][:55]}")
    print()


def cmd_playbooks(args):
    """List playbooks."""
    pbs = api("GET", "/api/config/playbooks") or []
    print(f"\n{C.BOLD}Playbooks ({len(pbs)}){C.RESET}\n")
    for p in pbs:
        status = f"{C.GREEN}ENABLED{C.RESET}" if p.get("enabled") else f"{C.RED}DISABLED{C.RESET}"
        approval = f" {C.YELLOW}[APPROVAL REQUIRED]{C.RESET}" if p.get("requires_approval") else ""
        print(f"  #{p['id']:>2} [{status}]{approval} {p['name']}")
        if p.get("actions"):
            for a in p["actions"]:
                print(f"       -> {a.get('type', '?')}: {a.get('description', '')[:50]}")
    print()


def cmd_detections(args):
    """List detection rules."""
    dets = api("GET", "/api/config/detections") or []
    print(f"\n{C.BOLD}Detection Rules ({len(dets)}){C.RESET}\n")
    for d in dets:
        status = f"{C.GREEN}ON{C.RESET}" if d.get("enabled") else f"{C.RED}OFF{C.RESET}"
        sev = d.get("severity", "?")
        color = SEV_COLOR.get(sev, "")
        print(f"  [{status}] {color}{sev.upper():>8}{C.RESET}  {d.get('name', '?')}")
    print()


def cmd_services(args):
    """Check Docker container status on VM (requires SSH via WSL)."""
    print(f"\n{C.BOLD}Docker Services{C.RESET}\n")
    output = ssh_cmd(f"cd /home/{VM_USER}/Lab-Repo && docker-compose ps 2>/dev/null || docker compose ps 2>/dev/null")
    print(output)

    print(f"\n{C.BOLD}SOC Agent Status{C.RESET}\n")
    output = ssh_cmd("systemctl is-active soc-agent 2>/dev/null && echo RUNNING || echo STOPPED")
    color = C.GREEN if "RUNNING" in output else C.RED
    print(f"  soc-agent: {color}{output}{C.RESET}")
    print()


def cmd_restart(args):
    """Restart Docker containers on VM (requires SSH via WSL)."""
    print(f"{C.YELLOW}Restarting Docker containers...{C.RESET}")
    output = ssh_cmd(f"cd /home/{VM_USER}/Lab-Repo && echo {VM_PASS} | sudo -S docker-compose restart 2>&1 || echo {VM_PASS} | sudo -S docker compose restart 2>&1")
    print(output)
    print(f"{C.GREEN}Restart complete.{C.RESET}")


def cmd_agent_status(args):
    """Check soc-agent systemd status."""
    output = ssh_cmd("systemctl status soc-agent --no-pager -l 2>/dev/null | head -20")
    print(output)


def cmd_seed(args):
    """Re-run the attack simulation."""
    print(f"{C.YELLOW}Running setup_soc.py on VM...{C.RESET}")
    output = ssh_cmd(f"cd /home/{VM_USER}/Lab-Repo && python3 scripts/setup_soc.py 2>&1")
    print(output)


def cmd_resolve_all(args):
    """Resolve all open incidents."""
    raw = api("GET", "/api/incidents?status=open&limit=200") or {}
    incidents = raw.get("incidents", []) if isinstance(raw, dict) else raw
    if not incidents:
        print(f"{C.GREEN}No open incidents.{C.RESET}")
        return
    count = 0
    for inc in incidents:
        result = api("PATCH", f"/api/incidents/{inc['id']}", body={"status": "resolved"})
        if result:
            count += 1
    print(f"{C.GREEN}Resolved {count}/{len(incidents)} incidents.{C.RESET}")


# -- Main ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Ataraxia SOC Remote Management Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python soc_manage.py status                          Full health check
  python soc_manage.py incidents --open                Open incidents only
  python soc_manage.py alarms --create "Test alarm"    Create an alarm
  python soc_manage.py logs --inject                   Inject test logs
  python soc_manage.py services                        Docker status (SSH)
  python soc_manage.py restart                         Restart containers (SSH)
  python soc_manage.py seed                            Re-run attack sim
  python soc_manage.py resolve-all                     Resolve all incidents
""",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status", help="Full SOC health dashboard")

    p_inc = sub.add_parser("incidents", help="List incidents")
    p_inc.add_argument("--open", action="store_true", help="Only open incidents")
    p_inc.add_argument("--severity", help="Filter by severity")

    p_log = sub.add_parser("logs", help="Log statistics")
    p_log.add_argument("--inject", action="store_true", help="Inject 10 test logs")

    p_alarm = sub.add_parser("alarms", help="List or create alarms")
    p_alarm.add_argument("--create", help="Create alarm with this message")
    p_alarm.add_argument("--ack", type=int, help="Acknowledge alarm by ID")
    p_alarm.add_argument("--severity", default="medium", help="Alarm severity")
    p_alarm.add_argument("--source", default="Manual", help="Alarm source")

    sub.add_parser("playbooks", help="List playbooks")
    sub.add_parser("detections", help="List detection rules")
    sub.add_parser("services", help="Docker service status (SSH)")
    sub.add_parser("restart", help="Restart containers (SSH)")
    sub.add_parser("agent-status", help="SOC agent systemd status (SSH)")
    sub.add_parser("seed", help="Re-run attack simulation")
    sub.add_parser("resolve-all", help="Resolve all open incidents")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    commands = {
        "status": cmd_status,
        "incidents": cmd_incidents,
        "logs": cmd_logs,
        "alarms": cmd_alarms,
        "playbooks": cmd_playbooks,
        "detections": cmd_detections,
        "services": cmd_services,
        "restart": cmd_restart,
        "agent-status": cmd_agent_status,
        "seed": cmd_seed,
        "resolve-all": cmd_resolve_all,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
