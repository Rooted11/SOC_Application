"""
Redis Stream worker for log processing.
Consumes the log stream, runs the pipeline (scoring, IOC correlation, incident/playbook),
and acks processed messages.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta

import redis

from .services.config import settings
from .services import event_bus
from .services.log_pipeline import process_log_payload
from .services.database import SessionLocal, Log, Incident, PlaybookAction, Alert


STREAM = settings.redis_stream_logs
GROUP = settings.redis_consumer_group
CONSUMER = event_bus.get_consumer_name()


def cleanup_old_data(cutoff: datetime) -> int:
    """Delete logs older than cutoff and related incidents/actions/alerts."""
    db = SessionLocal()
    try:
        old_logs = db.query(Log.id).filter(Log.timestamp < cutoff).subquery()
        old_incidents = db.query(Incident.id).filter(Incident.trigger_log_id.in_(old_logs)).subquery()

        pa_deleted = db.query(PlaybookAction).filter(PlaybookAction.incident_id.in_(old_incidents)).delete(synchronize_session=False)
        alerts_deleted = db.query(Alert).filter(Alert.incident_id.in_(old_incidents)).delete(synchronize_session=False)
        incidents_deleted = db.query(Incident).filter(Incident.id.in_(old_incidents)).delete(synchronize_session=False)
        logs_deleted = db.query(Log).filter(Log.id.in_(old_logs)).delete(synchronize_session=False)
        db.commit()
        return logs_deleted + incidents_deleted + pa_deleted + alerts_deleted
    finally:
        db.close()


def main() -> None:
    if not settings.use_redis_streams:
        print("USE_REDIS_STREAMS is false; worker exiting.")
        return

    client = event_bus.get_client()
    event_bus.ensure_consumer_group()

    print(f"[worker] listening on stream={STREAM}, group={GROUP}, consumer={CONSUMER}")

    last_cleanup = time.time()
    while True:
        try:
            messages = client.xreadgroup(
                groupname=GROUP,
                consumername=CONSUMER,
                streams={STREAM: ">"},
                count=25,
                block=5000,
            )
            if not messages:
                continue

            for stream_name, entries in messages:
                for entry_id, data in entries:
                    try:
                        payload = json.loads(data.get("log", "{}"))
                        ts = payload.get("timestamp")
                        if isinstance(ts, str):
                            try:
                                payload["timestamp"] = datetime.fromisoformat(ts)
                            except ValueError:
                                payload["timestamp"] = datetime.utcnow()
                        result = process_log_payload(payload)
                        client.xack(STREAM, GROUP, entry_id)
                        print(f"[worker] processed log_id={result['log_id']} anomalous={result['is_anomalous']} incident={result['incident_id']}")
                    except Exception as exc:
                        print(f"[worker] error processing entry {entry_id}: {exc}")
            now = time.time()
            if now - last_cleanup >= settings.log_retention_minutes * 60:
                cutoff = datetime.utcnow() - timedelta(minutes=settings.log_retention_minutes)
                deleted = cleanup_old_data(cutoff)
                print(f"[worker] retention cleanup removed {deleted} records older than {cutoff.isoformat()}")
                last_cleanup = now
        except redis.exceptions.ConnectionError as exc:
            print(f"[worker] redis connection error: {exc}; retrying in 2s")
            time.sleep(2)
        except Exception as exc:
            print(f"[worker] unexpected error: {exc}; continuing")


if __name__ == "__main__":
    main()
