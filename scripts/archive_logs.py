#!/usr/bin/env python3
"""
archive_logs.py
---------------
Archives logs older than RETAIN_HOURS from the SOC database to
compressed JSON files in /logs/archive/YYYY-MM-DD.json.gz
Then deletes the archived records from the DB (respecting FK relationships).

Run manually:  python3 scripts/archive_logs.py
Or via cron:   */10 * * * * DATABASE_URL=... python3 /path/to/archive_logs.py
"""
import gzip
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

RETAIN_HOURS = float(os.getenv("LOG_RETAIN_HOURS", "0.25"))
ARCHIVE_DIR  = Path(os.getenv("ARCHIVE_DIR", "/opt/soc-lab/logs/archive"))
DB_URL       = os.getenv("DATABASE_URL", "postgresql://soc:soc_pass@localhost:5432/soc_db")

ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

from sqlalchemy import create_engine, text

engine = create_engine(DB_URL)

cutoff = datetime.now(timezone.utc) - timedelta(hours=RETAIN_HOURS)

with engine.begin() as conn:
    # Fetch logs to archive
    rows = conn.execute(
        text("""
            SELECT id, source, timestamp, log_level, message, ip_src, ip_dst,
                   "user", event_type, anomaly_score, risk_score, is_anomalous,
                   explanation, asset_id, raw_data
            FROM logs
            WHERE timestamp < :cutoff
            ORDER BY timestamp ASC
        """),
        {"cutoff": cutoff},
    ).fetchall()

    if not rows:
        print(f"No logs older than {RETAIN_HOURS}h to archive.")
        sys.exit(0)

    # Group by date for archival
    by_date = {}
    for row in rows:
        d = row.timestamp.strftime("%Y-%m-%d") if row.timestamp else "unknown"
        by_date.setdefault(d, []).append({
            "id":           row.id,
            "source":       row.source,
            "timestamp":    row.timestamp.isoformat() if row.timestamp else None,
            "log_level":    row.log_level,
            "message":      row.message,
            "ip_src":       row.ip_src,
            "ip_dst":       row.ip_dst,
            "user":         row.user,
            "event_type":   row.event_type,
            "anomaly_score": float(row.anomaly_score or 0),
            "risk_score":   float(row.risk_score or 0),
            "is_anomalous": bool(row.is_anomalous),
            "explanation":  row.explanation,
            "asset_id":     row.asset_id,
        })

    archived_count = 0
    for date_str, log_list in by_date.items():
        archive_path = ARCHIVE_DIR / f"{date_str}.json.gz"
        existing = []
        if archive_path.exists():
            with gzip.open(archive_path, "rt") as f:
                existing = json.load(f)
        combined = existing + log_list
        with gzip.open(archive_path, "wt") as f:
            json.dump(combined, f, default=str)
        archived_count += len(log_list)
        print(f"  Archived {len(log_list)} logs to {archive_path}")

    # Delete in FK-safe order: playbook_actions -> alerts -> incidents -> logs
    log_ids = [row.id for row in rows]

    # Find incidents linked to these logs
    incident_rows = conn.execute(
        text("SELECT id FROM incidents WHERE trigger_log_id = ANY(:ids)"),
        {"ids": log_ids},
    ).fetchall()
    incident_ids = [r.id for r in incident_rows]

    if incident_ids:
        # Delete playbook actions for these incidents
        pa = conn.execute(
            text("DELETE FROM playbook_actions WHERE incident_id = ANY(:ids)"),
            {"ids": incident_ids},
        )
        print(f"  Removed {pa.rowcount} playbook actions")

        # Delete alerts for these incidents
        al = conn.execute(
            text("DELETE FROM alerts WHERE incident_id = ANY(:ids)"),
            {"ids": incident_ids},
        )
        print(f"  Removed {al.rowcount} alerts")

        # Delete incidents
        inc = conn.execute(
            text("DELETE FROM incidents WHERE id = ANY(:ids)"),
            {"ids": incident_ids},
        )
        print(f"  Removed {inc.rowcount} incidents")

    # Now safe to delete logs
    lg = conn.execute(
        text("DELETE FROM logs WHERE id = ANY(:ids)"),
        {"ids": log_ids},
    )
    print(f"  Removed {lg.rowcount} logs from DB")

    # engine.begin() auto-commits on exit

    print(f"\nTotal: {archived_count} logs archived and cleaned.")
    print(f"Archive directory: {ARCHIVE_DIR}")
    sizes = [(p.name, p.stat().st_size) for p in ARCHIVE_DIR.glob("*.json.gz")]
    for name, size in sorted(sizes):
        print(f"  {name}: {size/1024:.1f} KB")
