#!/usr/bin/env python3
"""
Log Simulator
=============
Continuously generates realistic log events and POSTs them to the
Ataraxia backend API in batches.

Usage:
    python scripts/simulate_logs.py [--url URL] [--interval SECONDS] [--count N]

Options:
    --url       Backend API URL (default: http://localhost:8000)
    --interval  Seconds between batches (default: 5)
    --count     Logs per batch (default: 3)
    --once      Send one batch then exit (useful for seeding)
"""

import argparse
import json
import random
import time
from datetime import datetime, timedelta

import urllib.request
import urllib.error

from auth_client import json_headers

# ── Event catalogue ──────────────────────────────────────────────────────────

NORMAL_EVENTS = [
    {"source": "auth",     "log_level": "info",    "event_type": "auth_success",    "message": "User {user} logged in from {ip}"},
    {"source": "syslog",   "log_level": "info",    "event_type": "service_start",   "message": "Service {service} started on {host}"},
    {"source": "syslog",   "log_level": "info",    "event_type": "file_access",     "message": "File accessed: /var/log/syslog by {user}"},
    {"source": "firewall", "log_level": "info",    "event_type": "dns_query",       "message": "DNS query to {domain} from {ip}"},
    {"source": "endpoint", "log_level": "info",    "event_type": "process_create",  "message": "Process {process} created by {user}"},
]

ATTACK_EVENTS = [
    {"source": "auth",     "log_level": "warning",  "event_type": "auth_failure",        "message": "Multiple failed logins from {ip} for user {user}"},
    {"source": "firewall", "log_level": "warning",  "event_type": "network_scan",        "message": "Port scan detected from {ip}"},
    {"source": "endpoint", "log_level": "critical", "event_type": "malware_detected",    "message": "Malware detected on {host}: {file}"},
    {"source": "auth",     "log_level": "error",    "event_type": "privilege_escalation","message": "Privilege escalation by {user} on {host}"},
    {"source": "endpoint", "log_level": "error",    "event_type": "lateral_movement",    "message": "RDP connection from {ip_src} to {ip_dst}"},
    {"source": "firewall", "log_level": "critical", "event_type": "c2_beacon",           "message": "C2 beacon to {domain} blocked"},
    {"source": "endpoint", "log_level": "error",    "event_type": "data_exfiltration",   "message": "Large data transfer to external IP {ip}"},
]

INTERNAL_IPS  = ["10.0.1.10","10.0.1.20","10.0.1.30","10.0.2.42","10.0.1.5","10.0.2.15"]
EXTERNAL_IPS  = ["185.220.101.55","203.0.113.88","198.51.100.200","91.108.4.200","45.142.212.100"]
USERS         = ["jsmith","jdoe","admin","svc_backup","svc_monitor","krbtgt","www-data","root"]
SERVICES      = ["nginx","postgresql","sshd","cron","docker","systemd-resolved"]
PROCESSES     = ["python3","bash","powershell.exe","cmd.exe","svchost.exe","explorer.exe"]
DOMAINS       = ["evil-c2.xyz","malicious-update.ru","update-win32-patch.cn","google.com","internal.corp"]
FILES         = ["invoice.exe","update.msi","payload.dll","report.pdf","normal_doc.docx"]
HOSTS         = ["web-server-01","db-server-01","workstation-42","mail-server-01","dc-server-01"]


def make_log(attack: bool = False) -> dict:
    """Generate a single synthetic log event dict."""
    template = random.choice(ATTACK_EVENTS if attack else NORMAL_EVENTS)
    ip_src   = random.choice(EXTERNAL_IPS if attack else INTERNAL_IPS)
    ip_dst   = random.choice(INTERNAL_IPS)
    user     = random.choice(USERS)
    host     = random.choice(HOSTS)
    domain   = random.choice(DOMAINS)

    message = template["message"].format(
        ip=ip_src, ip_src=ip_src, ip_dst=ip_dst,
        user=user, host=host, domain=domain,
        service=random.choice(SERVICES),
        process=random.choice(PROCESSES),
        file=random.choice(FILES),
    )

    # Add slight jitter to timestamp
    ts = datetime.utcnow() - timedelta(seconds=random.randint(0, 10))

    log = {
        "source":     template["source"],
        "timestamp":  ts.isoformat() + "Z",
        "log_level":  template["log_level"],
        "message":    message,
        "ip_src":     ip_src,
        "ip_dst":     ip_dst,
        "user":       user,
        "event_type": template["event_type"],
        "raw_data": {
            "host":     host,
            "dst_port": random.choice([22, 80, 443, 445, 3389, 8080, 9200]),
        },
    }

    # Inject known-malicious IPs occasionally to trigger IOC correlation
    if attack and random.random() < 0.3:
        log["ip_src"] = random.choice(["185.220.101.55", "198.51.100.200", "203.0.113.88"])

    return log


def send_batch(url: str, logs: list, headers: dict[str, str]) -> dict:
    payload = json.dumps({"logs": logs}).encode()
    req = urllib.request.Request(
        f"{url}/api/logs/ingest",
        data=payload,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def main():
    parser = argparse.ArgumentParser(description="Ataraxia log simulator")
    parser.add_argument("--url",      default="http://localhost:8000", help="Backend URL")
    parser.add_argument("--interval", type=float, default=5,           help="Seconds between batches")
    parser.add_argument("--count",    type=int,   default=3,           help="Logs per batch")
    parser.add_argument("--once",     action="store_true",             help="Send one batch and exit")
    args = parser.parse_args()
    headers = json_headers(args.url)

    print(f"Ataraxia Log Simulator → {args.url}")
    print(f"Sending {args.count} logs every {args.interval}s  (Ctrl-C to stop)\n")

    batch_num = 0
    while True:
        batch_num += 1
        # ~20% of batches contain at least one attack event
        logs = []
        for _ in range(args.count):
            is_attack = random.random() < 0.20
            logs.append(make_log(attack=is_attack))

        try:
            result = send_batch(args.url, logs, headers)
            anomalous = sum(1 for r in result.get("results", []) if r.get("is_anomalous"))
            incidents = sum(1 for r in result.get("results", []) if r.get("incident_id"))
            ts = datetime.utcnow().strftime("%H:%M:%S")
            print(f"[{ts}] Batch {batch_num:04d}: "
                  f"{len(logs)} logs sent | "
                  f"{anomalous} anomalous | "
                  f"{incidents} incidents created")
        except Exception as exc:
            print(f"[ERROR] Batch {batch_num}: {exc}")

        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
