#!/usr/bin/env python3
"""
send_local_logs.py  --  Windows Endpoint Log Sender for Ataraxia SOC
=====================================================================
Collects Windows Event Logs from the local machine and forwards them
to the Ataraxia SOC backend for analysis.

Supported channels:
  - Security   (logon events 4624/4625, account changes, privilege use)
  - System     (service start/stop, errors)
  - Application (app crashes, errors)

Uses pywin32 (win32evtlog) when available; falls back to wevtutil via
subprocess if pywin32 is not installed.  The --demo flag generates
realistic synthetic events for testing without either dependency.

Usage examples:
  # Continuous mode (default: polls every 15 seconds)
  python scripts/send_local_logs.py

  # Single collection pass
  python scripts/send_local_logs.py --once

  # Demo mode (synthetic events, no Windows API needed)
  python scripts/send_local_logs.py --demo --once

  # Custom endpoint and token
  python scripts/send_local_logs.py --endpoint http://192.168.56.102:8000 --token lab-ingest-token
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib import request, error as urlerror

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_ENDPOINT = "http://192.168.56.102:8000/api/logs/ingest"
DEFAULT_TOKEN = "lab-ingest-token"
POLL_INTERVAL_SECONDS = 15

STATE_FILE = Path(__file__).resolve().parent / "state.json"

CHANNELS = ["Security", "System", "Application"]

# Map channel name -> SOC source label
CHANNEL_SOURCE_MAP = {
    "Security": "windows-security",
    "System": "windows-system",
    "Application": "windows-application",
}

# Map well-known Security event IDs -> SOC event_type
EVENT_ID_TYPE_MAP = {
    4624: "auth_success",
    4625: "auth_failure",
    4634: "logoff",
    4648: "explicit_logon",
    4672: "privilege_escalation",
    4688: "process_creation",
    4697: "service_install",
    4720: "account_change",
    4722: "account_change",
    4724: "account_change",
    4725: "account_change",
    4726: "account_change",
    4732: "group_membership_change",
    4733: "group_membership_change",
    4740: "account_lockout",
    4756: "group_membership_change",
    4767: "account_lockout",
    7034: "service_crash",
    7036: "service_state_change",
    7040: "service_config_change",
    7045: "service_install",
    1000: "app_error",
    1001: "app_error",
    1002: "app_hang",
}

# Windows event level integer -> SOC log_level string
LEVEL_MAP = {
    0: "info",       # LogAlways
    1: "critical",
    2: "error",
    3: "warning",
    4: "info",
    5: "info",       # Verbose
}

# ---------------------------------------------------------------------------
# pywin32 availability
# ---------------------------------------------------------------------------

try:
    import win32evtlog    # type: ignore[import-untyped]
    import win32evtlogutil  # type: ignore[import-untyped]
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False

# ---------------------------------------------------------------------------
# State persistence  (last-read record number per channel)
# ---------------------------------------------------------------------------


def load_state() -> Dict[str, int]:
    """Return {channel: last_record_number} from the local state file."""
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return {k: int(v) for k, v in data.items()}
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            print(f"[state] Warning: could not load {STATE_FILE}: {exc}")
    return {}


def save_state(state: Dict[str, int]) -> None:
    """Persist {channel: last_record_number} to the local state file."""
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)
    except OSError as exc:
        print(f"[state] Warning: could not save {STATE_FILE}: {exc}")

# ---------------------------------------------------------------------------
# Event field extraction helpers
# ---------------------------------------------------------------------------


def extract_username_from_message(message: str) -> Optional[str]:
    """Best-effort extraction of a username from an event message string."""
    # Common patterns in Windows Security logs:
    #   "Account Name:		SOMEUSER"
    #   "Target User Name:	SOMEUSER"
    for marker in ("Account Name:", "Target User Name:", "User Name:", "User:"):
        idx = message.find(marker)
        if idx != -1:
            rest = message[idx + len(marker):].lstrip()
            token = rest.split()[0] if rest.split() else None
            if token and token != "-":
                return token.strip()
    return None


def extract_ip_from_message(message: str) -> Optional[str]:
    """Best-effort extraction of a source IP from an event message string."""
    for marker in ("Source Network Address:", "Source Address:", "Client Address:", "IpAddress:"):
        idx = message.find(marker)
        if idx != -1:
            rest = message[idx + len(marker):].lstrip()
            token = rest.split()[0] if rest.split() else None
            if token and token not in ("-", "::1", "127.0.0.1"):
                return token.strip()
    return None


def map_event_type(channel: str, event_id: int) -> str:
    """Map a (channel, event_id) pair to a SOC event_type string."""
    if event_id in EVENT_ID_TYPE_MAP:
        return EVENT_ID_TYPE_MAP[event_id]
    # Generic fallback by channel
    if channel == "Security":
        return "security_other"
    if channel == "System":
        return "system_event"
    return "application_event"


def map_log_level(level: int) -> str:
    """Convert Windows event level integer to SOC log_level string."""
    return LEVEL_MAP.get(level, "info")

# ---------------------------------------------------------------------------
# Collector: pywin32 backend
# ---------------------------------------------------------------------------


def collect_pywin32(channel: str, last_record: int) -> List[Dict[str, Any]]:
    """Read new events from *channel* using pywin32, starting after *last_record*."""
    entries: List[Dict[str, Any]] = []
    hostname = socket.gethostname()

    try:
        handle = win32evtlog.OpenEventLog(None, channel)
    except Exception as exc:
        print(f"[pywin32] Could not open {channel}: {exc}")
        return entries

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    try:
        while True:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
            for ev in events:
                rec_num = ev.RecordNumber
                if rec_num <= last_record:
                    # We have caught up; stop reading.
                    win32evtlog.CloseEventLog(handle)
                    return entries

                event_id = ev.EventID & 0xFFFF  # mask to 16-bit
                level = ev.EventType  # 0-5

                # Format message
                try:
                    message = win32evtlogutil.SafeFormatMessage(ev, channel)
                except Exception:
                    message = f"EventID={event_id}"

                # Build SOC payload
                username = extract_username_from_message(message)
                ip_src = extract_ip_from_message(message)
                ts = ev.TimeGenerated.isoformat() + "Z" if hasattr(ev.TimeGenerated, "isoformat") else datetime.now(timezone.utc).isoformat()

                entries.append({
                    "source": CHANNEL_SOURCE_MAP[channel],
                    "timestamp": ts,
                    "log_level": map_log_level(level),
                    "message": message[:2000],  # truncate very long messages
                    "ip_src": ip_src,
                    "ip_dst": None,
                    "user": username,
                    "event_type": map_event_type(channel, event_id),
                    "raw_data": {
                        "hostname": hostname,
                        "event_id": event_id,
                        "channel": channel,
                        "record_number": rec_num,
                    },
                })
    except Exception as exc:
        print(f"[pywin32] Error reading {channel}: {exc}")
    finally:
        try:
            win32evtlog.CloseEventLog(handle)
        except Exception:
            pass

    return entries

# ---------------------------------------------------------------------------
# Collector: wevtutil subprocess fallback
# ---------------------------------------------------------------------------


def collect_wevtutil(channel: str, last_record: int, max_events: int = 50) -> List[Dict[str, Any]]:
    """Read recent events from *channel* using wevtutil.exe (no pywin32 needed)."""
    entries: List[Dict[str, Any]] = []
    hostname = socket.gethostname()

    try:
        result = subprocess.run(
            ["wevtutil", "qe", channel, "/c:" + str(max_events), "/f:xml", "/rd:true"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            print(f"[wevtutil] Error querying {channel}: {result.stderr.strip()}")
            return entries
        raw_xml = result.stdout
    except FileNotFoundError:
        print("[wevtutil] wevtutil.exe not found -- not running on Windows?")
        return entries
    except subprocess.TimeoutExpired:
        print(f"[wevtutil] Timeout querying {channel}")
        return entries
    except Exception as exc:
        print(f"[wevtutil] Unexpected error: {exc}")
        return entries

    # wevtutil outputs each <Event>...</Event> sequentially; wrap in a root to parse
    wrapped = f"<Events>{raw_xml}</Events>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError:
        # Try parsing events one at a time from raw output
        print(f"[wevtutil] XML parse error for {channel}; skipping batch")
        return entries

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    for event_el in root.findall("e:Event", ns):
        system_el = event_el.find("e:System", ns)
        if system_el is None:
            continue

        # Record number
        rec_el = system_el.find("e:EventRecordID", ns)
        rec_num = int(rec_el.text) if rec_el is not None and rec_el.text else 0
        if rec_num <= last_record:
            continue

        # Event ID
        eid_el = system_el.find("e:EventID", ns)
        event_id = int(eid_el.text) if eid_el is not None and eid_el.text else 0

        # Level
        level_el = system_el.find("e:Level", ns)
        level = int(level_el.text) if level_el is not None and level_el.text else 4

        # Timestamp
        tc_el = system_el.find("e:TimeCreated", ns)
        ts = tc_el.get("SystemTime", "") if tc_el is not None else ""
        if not ts:
            ts = datetime.now(timezone.utc).isoformat()

        # Best-effort message from EventData / Data elements
        event_data_el = event_el.find("e:EventData", ns)
        data_values: List[str] = []
        if event_data_el is not None:
            for data_el in event_data_el.findall("e:Data", ns):
                name = data_el.get("Name", "")
                val = data_el.text or ""
                if val:
                    data_values.append(f"{name}={val}" if name else val)
        message = f"EventID={event_id} " + "; ".join(data_values) if data_values else f"EventID={event_id}"

        # Extract username / IP from data values
        username = None
        ip_src = None
        for dv in data_values:
            if "TargetUserName=" in dv:
                username = dv.split("=", 1)[1].strip()
            elif "SubjectUserName=" in dv and username is None:
                username = dv.split("=", 1)[1].strip()
            if "IpAddress=" in dv:
                candidate = dv.split("=", 1)[1].strip()
                if candidate not in ("-", "::1", "127.0.0.1"):
                    ip_src = candidate

        entries.append({
            "source": CHANNEL_SOURCE_MAP[channel],
            "timestamp": ts,
            "log_level": map_log_level(level),
            "message": message[:2000],
            "ip_src": ip_src,
            "ip_dst": None,
            "user": username,
            "event_type": map_event_type(channel, event_id),
            "raw_data": {
                "hostname": hostname,
                "event_id": event_id,
                "channel": channel,
                "record_number": rec_num,
            },
        })

    return entries

# ---------------------------------------------------------------------------
# Collector dispatcher
# ---------------------------------------------------------------------------


def collect_channel(channel: str, last_record: int) -> List[Dict[str, Any]]:
    """Collect new events from *channel* using the best available backend."""
    if HAS_PYWIN32:
        return collect_pywin32(channel, last_record)
    return collect_wevtutil(channel, last_record)

# ---------------------------------------------------------------------------
# Demo log generator
# ---------------------------------------------------------------------------

DEMO_USERS = ["Administrator", "svc_backup", "jdoe", "analyst01", "SYSTEM", "LOCAL SERVICE"]
DEMO_IPS = ["192.168.56.101", "192.168.56.1", "10.0.0.15", "172.16.5.22", "203.0.113.50", "198.51.100.7"]


def generate_demo_logs(count: int = 12) -> List[Dict[str, Any]]:
    """
    Generate realistic Windows-style log entries for testing.
    Returns a list of dicts matching the SOC LogIngest schema.
    No pywin32 or wevtutil needed.
    """
    hostname = socket.gethostname()
    entries: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc)

    templates = [
        # (channel, event_id, level, message_template, event_type)
        ("Security", 4624, 4,
         "An account was successfully logged on. Account Name: {user} Source Network Address: {ip}",
         "auth_success"),
        ("Security", 4625, 4,
         "An account failed to log on. Account Name: {user} Source Network Address: {ip} Failure Reason: Unknown user name or bad password.",
         "auth_failure"),
        ("Security", 4625, 4,
         "An account failed to log on. Account Name: {user} Source Network Address: {ip} Failure Reason: Account locked out.",
         "auth_failure"),
        ("Security", 4672, 4,
         "Special privileges assigned to new logon. Account Name: {user} Privileges: SeDebugPrivilege, SeBackupPrivilege",
         "privilege_escalation"),
        ("Security", 4720, 4,
         "A user account was created. Account Name: {user} Target Account Name: new_user_01",
         "account_change"),
        ("Security", 4740, 4,
         "A user account was locked out. Account Name: {user} Caller Computer Name: WORKSTATION1",
         "account_lockout"),
        ("Security", 4688, 4,
         "A new process has been created. Creator Subject Account Name: {user} New Process Name: C:\\Windows\\System32\\cmd.exe",
         "process_creation"),
        ("System", 7036, 4,
         "The Windows Update service entered the running state.",
         "service_state_change"),
        ("System", 7036, 4,
         "The Windows Defender service entered the stopped state.",
         "service_state_change"),
        ("System", 7045, 4,
         "A service was installed in the system. Service Name: SuspiciousSvc Service File Name: C:\\Temp\\svc.exe",
         "service_install"),
        ("System", 7034, 2,
         "The Application Host Helper Service service terminated unexpectedly. It has done this 3 time(s).",
         "service_crash"),
        ("System", 1074, 4,
         "The process C:\\Windows\\system32\\shutdown.exe ({hostname}) has initiated the restart of computer {hostname}.",
         "system_event"),
        ("Application", 1000, 2,
         "Faulting application name: explorer.exe, version 10.0.22621.1, Faulting module name: ntdll.dll",
         "app_error"),
        ("Application", 1001, 2,
         "Windows Error Reporting: Fault bucket type 0, Event Name: APPCRASH, Application: chrome.exe",
         "app_error"),
        ("Application", 1002, 3,
         "The program iexplore.exe stopped interacting with Windows and was closed.",
         "app_hang"),
    ]

    for i in range(count):
        tmpl = random.choice(templates)
        channel, event_id, level, msg_tmpl, evt_type = tmpl
        user = random.choice(DEMO_USERS)
        ip = random.choice(DEMO_IPS)

        message = msg_tmpl.format(user=user, ip=ip, hostname=hostname)
        rec_num = 100000 + i

        entries.append({
            "source": CHANNEL_SOURCE_MAP[channel],
            "timestamp": now.isoformat(),
            "log_level": map_log_level(level),
            "message": message,
            "ip_src": ip if "Source Network Address" in message or "IpAddress" in message else None,
            "ip_dst": None,
            "user": user,
            "event_type": evt_type,
            "raw_data": {
                "hostname": hostname,
                "event_id": event_id,
                "channel": channel,
                "record_number": rec_num,
            },
        })

    return entries

# ---------------------------------------------------------------------------
# Network: send batch to the SOC backend
# ---------------------------------------------------------------------------


def send_logs(endpoint: str, token: str, logs: List[Dict[str, Any]]) -> bool:
    """POST a batch of logs to the SOC backend. Returns True on success."""
    payload = json.dumps({"logs": logs}).encode("utf-8")
    req = request.Request(
        endpoint,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-Agent-Token": token,
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            status_code = resp.status
            print(f"  -> HTTP {status_code}: {body}")
            return 200 <= status_code < 300
    except urlerror.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore") if hasattr(exc, "read") else ""
        print(f"  -> HTTP {exc.code}: {body}")
        return False
    except urlerror.URLError as exc:
        print(f"  -> Connection error: {exc.reason}")
        return False
    except Exception as exc:
        print(f"  -> Unexpected error: {exc}")
        return False

# ---------------------------------------------------------------------------
# Main collection loop
# ---------------------------------------------------------------------------


def collect_and_send(endpoint: str, token: str, demo: bool = False) -> int:
    """
    Collect events from all channels (or generate demo events) and send
    them to the SOC backend. Returns the number of events sent.
    """
    all_logs: List[Dict[str, Any]] = []

    if demo:
        print("[demo] Generating synthetic Windows event logs...")
        all_logs = generate_demo_logs(count=random.randint(5, 15))
        print(f"[demo] Generated {len(all_logs)} demo events")
    else:
        state = load_state()
        new_state = dict(state)

        for channel in CHANNELS:
            last_rec = state.get(channel, 0)
            print(f"[{channel}] Collecting events after record {last_rec}...")
            try:
                events = collect_channel(channel, last_rec)
            except Exception as exc:
                print(f"[{channel}] Error: {exc}")
                events = []

            if events:
                # Update high-water mark
                max_rec = max(
                    e["raw_data"]["record_number"] for e in events
                )
                new_state[channel] = max(last_rec, max_rec)
                all_logs.extend(events)
                print(f"[{channel}] Collected {len(events)} new events (latest record: {new_state[channel]})")
            else:
                print(f"[{channel}] No new events")

        save_state(new_state)

    if not all_logs:
        print("[send] No events to send.")
        return 0

    print(f"[send] Sending {len(all_logs)} events to {endpoint} ...")
    success = send_logs(endpoint, token, all_logs)
    if success:
        print(f"[send] Successfully sent {len(all_logs)} events.")
    else:
        print("[send] Failed to send events (will retry next cycle).")
    return len(all_logs) if success else 0

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Windows Endpoint Log Sender for Ataraxia SOC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python send_local_logs.py --once\n"
            "  python send_local_logs.py --demo --once\n"
            "  python send_local_logs.py --endpoint http://192.168.56.102:8000/api/logs/ingest\n"
        ),
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help=f"SOC backend ingest URL (default: {DEFAULT_ENDPOINT})",
    )
    parser.add_argument(
        "--token",
        default=DEFAULT_TOKEN,
        help=f"Agent ingest token (default: {DEFAULT_TOKEN})",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single collection pass and exit (no loop)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Generate synthetic demo events instead of reading real Windows logs",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=POLL_INTERVAL_SECONDS,
        help=f"Seconds between collection cycles (default: {POLL_INTERVAL_SECONDS})",
    )
    args = parser.parse_args()

    # Banner
    hostname = socket.gethostname()
    print("=" * 64)
    print("  Ataraxia SOC  --  Windows Endpoint Log Sender")
    print("=" * 64)
    print(f"  Hostname : {hostname}")
    print(f"  Platform : {platform.platform()}")
    print(f"  Backend  : {args.endpoint}")
    print(f"  Token    : {'*' * (len(args.token) - 4) + args.token[-4:]}")
    print(f"  Mode     : {'demo' if args.demo else 'live'}")
    print(f"  Loop     : {'single pass' if args.once else f'every {args.interval}s'}")
    if not args.demo:
        print(f"  Backend  : {'pywin32' if HAS_PYWIN32 else 'wevtutil (subprocess fallback)'}")
        print(f"  State    : {STATE_FILE}")
    print("=" * 64)
    print()

    if args.once:
        collect_and_send(args.endpoint, args.token, demo=args.demo)
    else:
        cycle = 0
        try:
            while True:
                cycle += 1
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"--- Cycle {cycle} [{ts}] ---")
                try:
                    collect_and_send(args.endpoint, args.token, demo=args.demo)
                except Exception as exc:
                    print(f"[error] Unhandled exception in cycle {cycle}: {exc}")
                print(f"--- Sleeping {args.interval}s ---\n")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[exit] Interrupted by user. Goodbye.")
            sys.exit(0)


if __name__ == "__main__":
    main()
