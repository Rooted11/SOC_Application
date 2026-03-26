#!/usr/bin/env python3
"""
Database initialisation + seed script.
Run this once to create tables and load sample data.

Usage (with Docker running):
    docker compose exec backend python /backend/scripts/init_db.py

Usage (local venv):
    cd ai-soc/backend
    python ../scripts/init_db.py
"""

import json
import sys
import time
import urllib.request
from pathlib import Path

from auth_client import json_headers

BACKEND_URL = "http://localhost:8000"
DATA_DIR    = Path(__file__).resolve().parent.parent / "data"

def wait_for_backend(url: str, retries: int = 12, delay: float = 5.0):
    for i in range(retries):
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=3) as r:
                if r.status == 200:
                    print(f"[OK] Backend is ready.")
                    return True
        except Exception:
            pass
        print(f"  Waiting for backend… ({i+1}/{retries})")
        time.sleep(delay)
    print("[ERROR] Backend did not become ready.")
    return False


def post(url: str, payload: dict, *, headers: dict[str, str] | None = None):
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url, data=data,
        headers=headers or {"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def main():
    print("=== Ataraxia Database Init & Seed ===\n")

    if not wait_for_backend(BACKEND_URL):
        sys.exit(1)

    headers = json_headers(BACKEND_URL)

    # 1. Load sample logs
    sample_logs_file = DATA_DIR / "sample_logs.json"
    if sample_logs_file.exists():
        with open(sample_logs_file) as fh:
            data = json.load(fh)
        logs = data.get("logs", [])
        result = post(f"{BACKEND_URL}/api/logs/ingest", {"logs": logs}, headers=headers)
        print(f"[LOGS] Ingested {result['ingested']} sample logs")
        anomalous = sum(1 for r in result.get("results",[]) if r.get("is_anomalous"))
        incidents = sum(1 for r in result.get("results",[]) if r.get("incident_id"))
        print(f"       → {anomalous} anomalous, {incidents} incidents created")
    else:
        print("[SKIP] sample_logs.json not found")

    # 2. Trigger threat feed refresh
    req = urllib.request.Request(
        f"{BACKEND_URL}/api/threat-intel/refresh",
        method="POST",
        headers=headers,
        data=b"{}",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        result = json.loads(r.read())
    print(f"[THREAT INTEL] Loaded {result.get('total_added',0)} indicators")

    print("\nSeed complete! Open http://localhost:3000 to view the dashboard.")


if __name__ == "__main__":
    main()
