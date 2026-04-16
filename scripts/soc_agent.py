#!/usr/bin/env python3
"""
soc_agent.py -- Ataraxia SOC Linux Log Agent
=============================================
Tails log files on the local host, parses entries, and forwards
them to the SOC backend via the /api/logs/ingest endpoint.

Features
--------
- Follows /var/log/syslog, /var/log/auth.log, /var/log/kern.log by default
- Persistent position tracking (survives restarts, handles log rotation)
- Exponential back-off retry on API failures
- Detects log level and event type from syslog content
- Configurable via environment variables or CLI flags
- Runs as a systemd service

Environment variables
---------------------
SOC_ENDPOINT    Backend URL             default: http://<SOC_UBUNTU_IP>:8000
SOC_TOKEN       Ingest token            default: lab-ingest-token
SOC_INTERVAL    Poll interval (secs)    default: 10
SOC_BATCH       Max logs per batch      default: 50
SOC_LOG_FILES   Comma-separated paths   default: auth.log,syslog,kern.log
SOC_STATE_FILE  Position state file     default: /tmp/soc_agent_state.json

Usage
-----
  python3 soc_agent.py                    # run continuously
  python3 soc_agent.py --once             # one shot, then exit
  python3 soc_agent.py --endpoint URL --token TOKEN
"""

import argparse
import json
import logging
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_ENDPOINT = os.getenv("SOC_ENDPOINT",   "http://<SOC_UBUNTU_IP>:8000")
DEFAULT_TOKEN    = os.getenv("SOC_TOKEN",      "lab-ingest-token")
DEFAULT_INTERVAL = int(os.getenv("SOC_INTERVAL",  "10"))
DEFAULT_BATCH    = int(os.getenv("SOC_BATCH",     "50"))
STATE_FILE       = os.getenv("SOC_STATE_FILE", "/tmp/soc_agent_state.json")
LOG_FILES        = [f.strip() for f in os.getenv(
    "SOC_LOG_FILES",
    "/var/log/auth.log,/var/log/syslog,/var/log/kern.log"
).split(",") if f.strip()]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [soc-agent] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("soc_agent")

# ---------------------------------------------------------------------------
# Syslog keyword -> severity
# ---------------------------------------------------------------------------
_LEVEL_RE = [
    (re.compile(r"\b(emerg|emergency|panic|crit|critical)\b", re.I), "critical"),
    (re.compile(r"\b(alert)\b",                                re.I), "critical"),
    (re.compile(r"\b(err|error|fail(ed)?|denied)\b",           re.I), "error"),
    (re.compile(r"\b(warn(ing)?)\b",                           re.I), "warning"),
    (re.compile(r"\b(notice|info)\b",                          re.I), "info"),
    (re.compile(r"\b(debug)\b",                                re.I), "info"),
]

_EVENT_RE = [
    (re.compile(r"Failed password|authentication failure|Invalid user",   re.I), "auth_failure"),
    (re.compile(r"Accepted (password|publickey)|session opened for user", re.I), "auth_success"),
    (re.compile(r"sudo:|su\[|COMMAND=",                                   re.I), "privilege_escalation"),
    (re.compile(r"useradd|userdel|groupadd|passwd\[",                     re.I), "account_change"),
    (re.compile(r"UFW|iptables.*DENY|iptables.*DROP",                     re.I), "firewall_event"),
    (re.compile(r"sshd\[",                                                 re.I), "ssh_event"),
    (re.compile(r"CRON\[|anacron",                                         re.I), "scheduled_task"),
    (re.compile(r"kernel:|Out of memory|OOM|segfault",                    re.I), "system_event"),
    (re.compile(r"/etc/shadow|/etc/passwd|/etc/sudoers",                  re.I), "sensitive_file_access"),
]


def detect_level(msg: str) -> str:
    for pattern, level in _LEVEL_RE:
        if pattern.search(msg):
            return level
    return "info"


def detect_event_type(msg: str) -> str:
    for pattern, etype in _EVENT_RE:
        if pattern.search(msg):
            return etype
    return "syslog"


def extract_user(msg: str):
    m = re.search(r"for(?:\s+invalid\s+user)?\s+(\w[\w.-]{0,31})\s+from", msg, re.I)
    if m:
        return m.group(1)
    m = re.search(r"\buser\s+([\w.-]+)", msg, re.I)
    return m.group(1) if m else None


def extract_ip(msg: str):
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", msg)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# State persistence (file position tracking)
# ---------------------------------------------------------------------------

def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(state: dict):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except OSError as exc:
        logger.warning("Could not save state: %s", exc)


# ---------------------------------------------------------------------------
# Log file tailing
# ---------------------------------------------------------------------------

def tail_file(path: str, last_pos: int) -> tuple:
    """Return (new_lines, new_pos). Handles log rotation."""
    try:
        stat = os.stat(path)
    except FileNotFoundError:
        return [], last_pos

    # Log rotation: file shrank
    if stat.st_size < last_pos:
        logger.info("Log rotation detected for %s, resetting position", path)
        last_pos = 0

    if stat.st_size == last_pos:
        return [], last_pos

    try:
        with open(path, errors="ignore") as f:
            f.seek(last_pos)
            lines = f.readlines()
            new_pos = f.tell()
        clean = [l.rstrip("\n") for l in lines if l.strip()]
        return clean, new_pos
    except (OSError, PermissionError) as exc:
        logger.warning("Cannot read %s: %s", path, exc)
        return [], last_pos


# ---------------------------------------------------------------------------
# API communication
# ---------------------------------------------------------------------------

def send_logs(endpoint: str, token: str, logs: list, retry: int = 3) -> bool:
    url     = endpoint.rstrip("/") + "/api/logs/ingest"
    payload = json.dumps({"logs": logs}).encode("utf-8")
    headers = {
        "Content-Type":  "application/json",
        "X-Agent-Token": token,
        "Authorization": "Bearer " + token,
    }

    for attempt in range(1, retry + 1):
        try:
            req = urllib_request.Request(url, data=payload, headers=headers, method="POST")
            with urllib_request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read())
                n = body.get("ingested", body.get("enqueued", len(logs)))
                logger.info("Sent %d logs (ingested/queued: %s)", len(logs), n)
                return True
        except HTTPError as exc:
            body = exc.read().decode(errors="ignore")
            logger.warning("HTTP %d: %s (attempt %d/%d)", exc.code, body[:120], attempt, retry)
        except URLError as exc:
            logger.warning("Network error: %s (attempt %d/%d)", exc, attempt, retry)
        except Exception as exc:
            logger.error("Unexpected error: %s (attempt %d/%d)", exc, attempt, retry)

        if attempt < retry:
            backoff = 2 ** attempt
            logger.info("Retrying in %ds...", backoff)
            time.sleep(backoff)

    return False


# ---------------------------------------------------------------------------
# Log entry builder
# ---------------------------------------------------------------------------

def build_entry(line: str, source: str, host_ip: str) -> dict:
    return {
        "source":     source,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "log_level":  detect_level(line),
        "message":    line[:2000],
        "ip_src":     extract_ip(line) or host_ip,
        "event_type": detect_event_type(line),
        "user":       extract_user(line),
        "raw_data":   {
            "host":     socket.gethostname(),
            "log_file": source,
        },
    }


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(endpoint: str, token: str, interval: int, batch_size: int, log_files: list):
    host_ip = socket.gethostbyname(socket.gethostname())
    logger.info("SOC Agent started | endpoint=%s | host=%s (%s)", endpoint, socket.gethostname(), host_ip)
    logger.info("Monitoring files: %s", ", ".join(log_files))

    state = load_state()

    while True:
        batch = []

        for log_file in log_files:
            last_pos = state.get(log_file, 0)
            lines, new_pos = tail_file(log_file, last_pos)
            if lines:
                source = Path(log_file).stem
                for line in lines[-batch_size:]:
                    batch.append(build_entry(line, source, host_ip))
                state[log_file] = new_pos

        if batch:
            for i in range(0, len(batch), batch_size):
                chunk = batch[i : i + batch_size]
                ok = send_logs(endpoint, token, chunk)
                if not ok:
                    logger.error("Batch send failed for %d logs; will retry next cycle", len(chunk))
            save_state(state)

        time.sleep(interval)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Ataraxia SOC Linux Log Agent")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT,
                        help="SOC backend base URL")
    parser.add_argument("--token",    default=DEFAULT_TOKEN,
                        help="Ingest token (X-Agent-Token header)")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                        help="Poll interval in seconds")
    parser.add_argument("--batch",    type=int, default=DEFAULT_BATCH,
                        help="Max logs per API call")
    parser.add_argument("--files",    default=",".join(LOG_FILES),
                        help="Comma-separated log file paths to monitor")
    parser.add_argument("--once",     action="store_true",
                        help="Run one cycle then exit (testing mode)")
    args = parser.parse_args()

    files = [f.strip() for f in args.files.split(",") if f.strip()]

    if args.once:
        host_ip = socket.gethostbyname(socket.gethostname())
        state   = load_state()
        batch   = []
        for log_file in files:
            last_pos = state.get(log_file, 0)
            lines, new_pos = tail_file(log_file, last_pos)
            if lines:
                source = Path(log_file).stem
                for line in lines[-args.batch:]:
                    batch.append(build_entry(line, source, host_ip))
                state[log_file] = new_pos
        if batch:
            ok = send_logs(args.endpoint, args.token, batch)
            print("Sent {} logs - {}".format(len(batch), "OK" if ok else "FAILED"))
            if ok:
                save_state(state)
        else:
            print("No new lines to send.")
        return

    try:
        run(args.endpoint, args.token, args.interval, args.batch, files)
    except KeyboardInterrupt:
        logger.info("Agent stopped by user.")


if __name__ == "__main__":
    main()
