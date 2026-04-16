#!/usr/bin/env python3
"""
setup_soc.py -- One-shot script to seed the SOC with playbooks, alarms, and attack data.
Run on the Ubuntu VM: python3 setup_soc.py
"""
import json
import time
import random
from datetime import datetime, timezone, timedelta
from urllib import request as urllib_request
from urllib.error import HTTPError

BASE = "http://localhost:8000"

# ── Auth ──────────────────────────────────────────────────────────────────────
def get_token():
    data = json.dumps({"username": "soc_operator", "password": "change-me-locally"}).encode()
    req = urllib_request.Request(f"{BASE}/api/auth/login", data=data,
                                headers={"Content-Type": "application/json"}, method="POST")
    with urllib_request.urlopen(req) as resp:
        return json.loads(resp.read())["access_token"]

def api(method, path, body=None, token=None, agent_token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if agent_token:
        headers["X-Agent-Token"] = agent_token
        headers["Authorization"] = f"Bearer {agent_token}"
    data = json.dumps(body).encode() if body else None
    req = urllib_request.Request(f"{BASE}{path}", data=data, headers=headers, method=method)
    try:
        with urllib_request.urlopen(req) as resp:
            if resp.status == 204:
                return None
            return json.loads(resp.read())
    except HTTPError as e:
        err = e.read().decode(errors="ignore")
        print(f"  HTTP {e.code}: {err[:200]}")
        return None

# ── Playbooks ─────────────────────────────────────────────────────────────────
PLAYBOOKS = [
    {
        "name": "Brute Force Response",
        "description": "Blocks attacking IP and revokes credentials after repeated auth failures.",
        "enabled": True,
        "requires_approval": False,
        "triggers": [{"event_type": "auth_failure", "threshold": 5, "window_minutes": 10}],
        "conditions": {"min_severity": "medium", "event_types": ["auth_failure"]},
        "actions": [
            {"type": "block_ip", "description": "Add source IP to firewall deny-list"},
            {"type": "revoke_credentials", "description": "Disable targeted user account"},
            {"type": "send_alert", "channels": ["slack", "email"], "description": "Notify SOC analysts"},
        ],
    },
    {
        "name": "Host Isolation",
        "description": "Quarantines compromised host via EDR, collects forensics, alerts SOC.",
        "enabled": True,
        "requires_approval": False,
        "triggers": [{"event_type": "malware_detected"}, {"event_type": "c2_beacon"}, {"event_type": "lateral_movement"}],
        "conditions": {"min_severity": "high", "event_types": ["malware_detected", "c2_beacon", "lateral_movement"]},
        "actions": [
            {"type": "isolate_host", "description": "Send quarantine command to EDR"},
            {"type": "collect_forensics", "description": "Trigger memory dump and disk snapshot"},
            {"type": "send_alert", "channels": ["slack", "pagerduty"], "description": "Page on-call analyst"},
        ],
    },
    {
        "name": "Credential Compromise Response",
        "description": "Disables compromised accounts, forces password reset, revokes sessions.",
        "enabled": True,
        "requires_approval": False,
        "triggers": [{"event_type": "privilege_escalation"}, {"event_type": "account_change"}],
        "conditions": {"min_severity": "medium", "event_types": ["privilege_escalation", "account_change"]},
        "actions": [
            {"type": "revoke_credentials", "description": "Disable account and revoke tokens"},
            {"type": "send_alert", "channels": ["email", "slack"], "description": "Notify security team"},
        ],
    },
    {
        "name": "Lateral Movement Containment",
        "description": "Isolates source and destination hosts, blocks lateral IPs, collects forensics.",
        "enabled": True,
        "requires_approval": True,
        "triggers": [{"event_type": "lateral_movement", "severity": ["high", "critical"]}],
        "conditions": {"min_severity": "high", "event_types": ["lateral_movement"]},
        "actions": [
            {"type": "isolate_host", "description": "Quarantine source host"},
            {"type": "isolate_host", "description": "Quarantine destination host"},
            {"type": "block_ip", "description": "Block lateral movement IPs"},
            {"type": "collect_forensics", "description": "Collect artifacts from both endpoints"},
            {"type": "send_alert", "channels": ["slack", "pagerduty", "email"], "description": "Alert full SOC team"},
        ],
    },
    {
        "name": "Full Incident Response",
        "description": "Maximum response for critical incidents: isolate, revoke, block, forensics, alert all.",
        "enabled": True,
        "requires_approval": False,
        "triggers": [{"severity": ["critical"]}, {"event_type": "data_exfiltration"}],
        "conditions": {"min_severity": "critical"},
        "actions": [
            {"type": "isolate_host", "description": "Quarantine all affected hosts via EDR"},
            {"type": "revoke_credentials", "description": "Disable all associated accounts"},
            {"type": "block_ip", "description": "Block all malicious IPs at perimeter"},
            {"type": "collect_forensics", "description": "Full forensic collection"},
            {"type": "send_alert", "channels": ["slack", "email", "pagerduty"], "description": "Page entire IR team"},
        ],
    },
    {
        "name": "Threat Intel Match Alert",
        "description": "Alerts when a log matches known threat intelligence indicators.",
        "enabled": True,
        "requires_approval": False,
        "triggers": [{"condition": "threat_intel_match"}],
        "conditions": {"threat_intel_matched": True},
        "actions": [
            {"type": "block_ip", "description": "Block matched indicator IP"},
            {"type": "send_alert", "channels": ["slack", "email"], "description": "Notify threat intel team"},
        ],
    },
    {
        "name": "Data Exfiltration Response",
        "description": "Emergency response for data exfiltration: isolation, revocation, forensics.",
        "enabled": True,
        "requires_approval": False,
        "triggers": [{"event_type": "data_exfiltration"}],
        "conditions": {"min_severity": "high", "event_types": ["data_exfiltration"]},
        "actions": [
            {"type": "isolate_host", "description": "Network isolate exfiltrating host"},
            {"type": "block_ip", "description": "Block destination IPs/domains"},
            {"type": "revoke_credentials", "description": "Revoke credentials from affected host"},
            {"type": "collect_forensics", "description": "Capture network traffic and disk image"},
            {"type": "send_alert", "channels": ["slack", "pagerduty", "email"], "description": "Activate IR team"},
        ],
    },
]

# ── Alarms ────────────────────────────────────────────────────────────────────
ALARMS = [
    {"source": "Detection Engine", "message": "SSH Brute Force detected from 10.0.0.45 - 47 failed attempts in 3 minutes targeting root account", "severity": "critical"},
    {"source": "Threat Intel", "message": "Communication detected with known C2 server 185.220.101.34 (APT29 infrastructure)", "severity": "critical"},
    {"source": "Anomaly Detection", "message": "Unusual outbound data transfer: 2.3 GB to external IP 203.0.113.50 from web-server-01", "severity": "high"},
    {"source": "Detection Engine", "message": "Privilege escalation: user 'jsmith' added to sudoers group outside change window", "severity": "high"},
    {"source": "Log Pipeline", "message": "Log ingestion rate dropped 85% from kali-linux host - possible agent failure or tampering", "severity": "medium"},
    {"source": "Firewall", "message": "Port scan detected from 10.0.0.99 - 1,247 ports probed on internal subnet 192.168.1.0/24", "severity": "medium"},
    {"source": "Anomaly Detection", "message": "ML model flagged anomalous login pattern: user 'admin' authenticated from 3 countries in 1 hour", "severity": "high"},
    {"source": "SIEM Correlation", "message": "Kill chain progression: recon -> exploitation -> lateral movement detected across 3 hosts", "severity": "critical"},
]

# ── Attack Simulation Logs ────────────────────────────────────────────────────
def generate_attack_logs():
    now = datetime.now(timezone.utc)
    logs = []

    # Scenario 1: SSH Brute Force from external IP
    attacker_ip = "10.0.0.45"
    for i in range(15):
        ts = (now - timedelta(minutes=random.randint(1, 10))).isoformat()
        users = ["root", "admin", "ubuntu", "kali", "postgres", "deploy"]
        user = random.choice(users)
        logs.append({
            "source": "auth",
            "timestamp": ts,
            "log_level": "error",
            "message": f"Failed password for {user} from {attacker_ip} port {random.randint(40000,60000)} ssh2",
            "ip_src": attacker_ip,
            "event_type": "auth_failure",
            "user": user,
            "raw_data": {"host": "kali-linux", "log_file": "auth.log"},
        })

    # Scenario 2: Successful breach after brute force
    logs.append({
        "source": "auth",
        "timestamp": (now - timedelta(minutes=1)).isoformat(),
        "log_level": "warning",
        "message": f"Accepted password for root from {attacker_ip} port 52341 ssh2",
        "ip_src": attacker_ip,
        "event_type": "auth_success",
        "user": "root",
        "raw_data": {"host": "kali-linux", "log_file": "auth.log"},
    })

    # Scenario 3: Privilege escalation
    logs.append({
        "source": "auth",
        "timestamp": (now - timedelta(seconds=45)).isoformat(),
        "log_level": "warning",
        "message": f"sudo: jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=/bin/bash",
        "ip_src": "192.168.1.20",
        "event_type": "privilege_escalation",
        "user": "jsmith",
        "raw_data": {"host": "web-server-01", "log_file": "auth.log"},
    })

    # Scenario 4: Lateral movement (SSH from compromised host)
    logs.append({
        "source": "auth",
        "timestamp": (now - timedelta(seconds=30)).isoformat(),
        "log_level": "error",
        "message": f"sshd[4521]: Accepted publickey for deploy from 192.168.1.20 port 48123 ssh2",
        "ip_src": "192.168.1.20",
        "event_type": "lateral_movement",
        "user": "deploy",
        "raw_data": {"host": "db-server-01", "log_file": "auth.log"},
    })

    # Scenario 5: C2 beacon communication
    c2_ip = "185.220.101.34"
    for i in range(5):
        ts = (now - timedelta(seconds=random.randint(10, 120))).isoformat()
        logs.append({
            "source": "syslog",
            "timestamp": ts,
            "log_level": "critical",
            "message": f"kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.20 DST={c2_ip} PROTO=TCP DPT=443 LEN=52",
            "ip_src": c2_ip,
            "event_type": "c2_beacon",
            "user": None,
            "raw_data": {"host": "web-server-01", "log_file": "kern.log"},
        })

    # Scenario 6: Data exfiltration
    logs.append({
        "source": "syslog",
        "timestamp": (now - timedelta(seconds=15)).isoformat(),
        "log_level": "critical",
        "message": "Large outbound transfer detected: 2.3GB to 203.0.113.50:443 from web-server-01 (anomalous)",
        "ip_src": "203.0.113.50",
        "event_type": "data_exfiltration",
        "user": "www-data",
        "raw_data": {"host": "web-server-01", "log_file": "syslog"},
    })

    # Scenario 7: Port scanning
    scanner_ip = "10.0.0.99"
    for i in range(8):
        port = random.choice([22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200])
        ts = (now - timedelta(minutes=random.randint(5, 15))).isoformat()
        logs.append({
            "source": "kern",
            "timestamp": ts,
            "log_level": "warning",
            "message": f"kernel: [UFW BLOCK] IN=eth0 OUT= SRC={scanner_ip} DST=192.168.1.{random.randint(1,254)} PROTO=TCP DPT={port}",
            "ip_src": scanner_ip,
            "event_type": "firewall_event",
            "user": None,
            "raw_data": {"host": "kali-linux", "log_file": "kern.log"},
        })

    # Scenario 8: Malware detected
    logs.append({
        "source": "syslog",
        "timestamp": (now - timedelta(seconds=20)).isoformat(),
        "log_level": "critical",
        "message": "ClamAV: /tmp/.hidden/payload.elf: Trojan.Linux.Agent-123456 FOUND (quarantined)",
        "ip_src": "192.168.1.20",
        "event_type": "malware_detected",
        "user": "www-data",
        "raw_data": {"host": "web-server-01", "log_file": "syslog"},
    })

    # Scenario 9: Sensitive file access
    logs.append({
        "source": "auth",
        "timestamp": (now - timedelta(seconds=25)).isoformat(),
        "log_level": "warning",
        "message": "audit: user=jsmith accessed /etc/shadow (read) from TTY pts/0",
        "ip_src": "192.168.1.20",
        "event_type": "sensitive_file_access",
        "user": "jsmith",
        "raw_data": {"host": "web-server-01", "log_file": "auth.log"},
    })

    # Scenario 10: Account tampering
    logs.append({
        "source": "auth",
        "timestamp": (now - timedelta(seconds=22)).isoformat(),
        "log_level": "error",
        "message": "useradd[8821]: new user: name=backdoor, UID=0, GID=0, home=/root, shell=/bin/bash",
        "ip_src": "192.168.1.20",
        "event_type": "account_change",
        "user": "root",
        "raw_data": {"host": "web-server-01", "log_file": "auth.log"},
    })

    # Normal baseline logs
    normal_users = ["soc_operator", "analyst1", "deploy", "nginx"]
    for i in range(20):
        ts = (now - timedelta(minutes=random.randint(1, 60))).isoformat()
        user = random.choice(normal_users)
        messages = [
            f"sshd[{random.randint(1000,9999)}]: Accepted publickey for {user} from <VM_HOST_IP> port {random.randint(40000,60000)}",
            f"CRON[{random.randint(1000,9999)}]: (root) CMD (/usr/bin/python3 /opt/check_health.py)",
            f"systemd[1]: Started Session {random.randint(100,999)} of user {user}.",
            f"sshd[{random.randint(1000,9999)}]: Received disconnect from <VM_HOST_IP> port {random.randint(40000,60000)}:11: disconnected by user",
            f"kernel: [UFW ALLOW] IN=eth0 OUT= SRC=<VM_HOST_IP> DST=<SOC_UBUNTU_IP> PROTO=TCP DPT=22",
        ]
        logs.append({
            "source": random.choice(["auth", "syslog", "kern"]),
            "timestamp": ts,
            "log_level": "info",
            "message": random.choice(messages),
            "ip_src": "<VM_HOST_IP>",
            "event_type": random.choice(["ssh_event", "scheduled_task", "system_event", "syslog"]),
            "user": user,
            "raw_data": {"host": "kali-linux", "log_file": random.choice(["auth.log", "syslog", "kern.log"])},
        })

    return logs


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  Ataraxia SOC Setup Script")
    print("=" * 60)

    print("\n[1/4] Authenticating...")
    token = get_token()
    print(f"  Token: {token[:20]}...")

    # ── Create Playbooks ──
    print("\n[2/4] Creating playbooks...")
    existing = api("GET", "/api/config/playbooks", token=token) or []
    existing_names = {p["name"] for p in existing}
    created_pb = 0
    for pb in PLAYBOOKS:
        if pb["name"] in existing_names:
            print(f"  SKIP (exists): {pb['name']}")
            continue
        result = api("POST", "/api/config/playbooks", body=pb, token=token)
        if result:
            print(f"  CREATED: {pb['name']} (id={result['id']})")
            created_pb += 1
        else:
            print(f"  FAILED: {pb['name']}")
    print(f"  Total: {created_pb} new playbooks ({len(existing)} already existed)")

    # ── Create Alarms ──
    print("\n[3/4] Creating alarms...")
    created_alarms = 0
    for alarm in ALARMS:
        result = api("POST", "/api/alarms", body=alarm, token=token)
        if result:
            print(f"  ALARM [{alarm['severity'].upper():>8}]: {alarm['message'][:70]}...")
            created_alarms += 1
        else:
            print(f"  FAILED: {alarm['message'][:50]}")
    print(f"  Total: {created_alarms} alarms created")

    # ── Inject Attack Logs ──
    print("\n[4/4] Injecting attack simulation logs...")
    logs = generate_attack_logs()
    print(f"  Generated {len(logs)} logs ({len([l for l in logs if l['log_level'] in ('error','critical','warning')])} malicious, {len([l for l in logs if l['log_level'] == 'info'])} baseline)")

    # Send in batches of 25
    agent_token = "lab-ingest-token"
    total_sent = 0
    for i in range(0, len(logs), 25):
        batch = logs[i:i+25]
        result = api("POST", "/api/logs/ingest", body={"logs": batch}, agent_token=agent_token)
        if result:
            ingested = result.get("ingested", result.get("enqueued", len(batch)))
            total_sent += ingested
            print(f"  Batch {i//25 + 1}: sent {len(batch)} logs (ingested/queued: {ingested})")
        else:
            print(f"  Batch {i//25 + 1}: FAILED")
        time.sleep(0.5)

    print(f"  Total: {total_sent} logs ingested")

    # ── Verify ──
    print("\n" + "=" * 60)
    print("  Verification")
    print("=" * 60)

    playbooks = api("GET", "/api/config/playbooks", token=token) or []
    print(f"\n  Playbooks:  {len(playbooks)}")
    for p in playbooks:
        status = "ENABLED" if p.get("enabled") else "DISABLED"
        print(f"    [{status:>8}] {p['name']}")

    alarms = api("GET", "/api/alarms", token=token) or []
    print(f"\n  Alarms:     {len(alarms)}")
    for a in alarms[-5:]:
        print(f"    [{a['severity'].upper():>8}] {a['message'][:70]}")

    overview = api("GET", "/api/overview", token=token)
    if overview:
        print(f"\n  Dashboard Overview:")
        for key, val in overview.items():
            print(f"    {key}: {val}")

    incidents = api("GET", "/api/incidents", token=token)
    if incidents and isinstance(incidents, list):
        print(f"\n  Incidents:  {len(incidents)}")
        for inc in incidents[:10]:
            sev = inc.get("severity", "?")
            title = inc.get("title", "?")
            status = inc.get("status", "?")
            print(f"    [{sev.upper():>8}] [{status:>13}] {title[:60]}")

    log_stats = api("GET", "/api/logs/stats", token=token)
    if log_stats:
        print(f"\n  Log Stats:  {log_stats}")

    print("\n" + "=" * 60)
    print("  SOC Setup Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
