"""
Log ingestion and analysis routes.
POST /api/logs/ingest  — ingest one or many logs, queue or process
GET  /api/logs         — paginated log list with filters
POST /api/logs/analyze — re-score existing logs
GET  /api/logs/stats   — summary statistics
"""

from datetime import datetime
from typing import List, Optional
import hmac
import os

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..services.database import (
    get_db, Log, Asset, Incident, Alert, PlaybookAction, SeverityEnum, StatusEnum
)
from ..services.anomaly_detection import detector
from ..services.threat_intel import threat_intel
from ..services.config import settings
from ..services.security import get_current_user, AuthenticatedUser
from ..services import event_bus, log_pipeline
from app.logging_config import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/logs", tags=["logs"])


# ── Pydantic schemas ────────────────────────────────────────────────────────

class LogIngest(BaseModel):
    source:     str
    timestamp:  Optional[datetime] = None
    log_level:  Optional[str]      = "info"
    message:    str
    ip_src:     Optional[str]      = None
    ip_dst:     Optional[str]      = None
    user:       Optional[str]      = None
    event_type: Optional[str]      = "unknown"
    raw_data:   Optional[dict]     = {}


class LogBatch(BaseModel):
    logs: List[LogIngest]


# ── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/ingest")
async def ingest_logs(
    payload: LogBatch,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Ingest a batch of logs.
    If USE_REDIS_STREAMS=true, enqueue to Redis Streams for async processing and return 202.
    Otherwise, process synchronously (legacy path).
    """
    token_header = request.headers.get("x-agent-token")
    auth_header  = request.headers.get("authorization", "")
    bearer_token = auth_header.split(" ", 1)[1] if auth_header.lower().startswith("bearer ") else None
    client_ip    = request.client.host if request and request.client else "unknown"
    allowed_ips  = {settings.primary_asset_ip, "127.0.0.1", "localhost", "172.18.0.1"}

    token_ok = False
    if settings.ingest_token:
        if token_header and hmac.compare_digest(token_header, settings.ingest_token):
            token_ok = True
        if bearer_token and hmac.compare_digest(bearer_token, settings.ingest_token):
            token_ok = True

    if not token_ok and settings.ingest_token and client_ip not in allowed_ips:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required (bearer token or X-Agent-Token).",
        )

    logs = []
    for entry in payload.logs:
        log_dict = entry.model_dump()
        log_dict["timestamp"] = log_dict.get("timestamp") or datetime.utcnow()
        logs.append(log_dict)

    if settings.use_redis_streams:
        try:
            event_bus.ensure_consumer_group()
            count, ids = event_bus.publish_logs(logs)
            return JSONResponse(
                {"enqueued": count, "stream_ids": ids, "mode": "queued"},
                status_code=status.HTTP_202_ACCEPTED,
            )
        except Exception as exc:
            logger.warning("Redis unavailable, falling back to inline processing: %s", exc)

    # Legacy synchronous path (also used if Redis is unavailable)
    results = [log_pipeline.process_log(db, log) for log in logs]
    return {"ingested": len(results), "results": results}


@router.get("")
def get_logs(
    source:      Optional[str]  = Query(None),
    anomalous:   Optional[bool] = Query(None),
    min_risk:    float          = Query(0.0),
    skip:        int            = Query(0, ge=0),
    limit:       int            = Query(50, le=200),
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return paginated, filtered log list."""
    q = db.query(Log)
    if source:
        q = q.filter(Log.source == source)
    if anomalous is not None:
        q = q.filter(Log.is_anomalous == anomalous)
    if min_risk > 0:
        q = q.filter(Log.risk_score >= min_risk)
    total = q.count()
    logs  = q.order_by(Log.timestamp.desc()).offset(skip).limit(limit).all()
    return {
        "total": total,
        "skip":  skip,
        "limit": limit,
        "logs":  [_log_to_dict(l) for l in logs],
    }


@router.get("/stats")
def log_stats(
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Summary statistics for the dashboard."""
    total     = db.query(Log).count()
    anomalous = db.query(Log).filter(Log.is_anomalous == True).count()
    from sqlalchemy import func
    avg_risk  = db.query(func.avg(Log.risk_score)).scalar() or 0.0
    by_source = (
        db.query(Log.source, func.count(Log.id))
        .group_by(Log.source)
        .all()
    )
    return {
        "total_logs":       total,
        "anomalous_logs":   anomalous,
        "anomaly_rate_pct": round(anomalous / total * 100, 1) if total else 0,
        "avg_risk_score":   round(float(avg_risk), 2),
        "by_source":        {s: c for s, c in by_source},
    }


@router.post("/analyze")
def analyze_logs(
    limit: int = Query(100, le=500),
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Re-score the most recent N unscored logs."""
    logs = (
        db.query(Log)
        .filter(Log.anomaly_score == 0.0)
        .order_by(Log.timestamp.desc())
        .limit(limit)
        .all()
    )
    updated = 0
    for log in logs:
        d = _log_to_dict(log)
        r = detector.score_log(d)
        log.anomaly_score = r["anomaly_score"]
        log.risk_score    = r["risk_score"]
        log.is_anomalous  = r["is_anomalous"]
        log.explanation   = r["explanation"]
        updated += 1
    db.commit()
    return {"re_scored": updated}


# ── Delete / Archive ───────────────────────────────────────────────────────

def _cascade_delete_logs(db: Session, log_ids: list[int]) -> dict:
    """Delete logs and all FK-dependent rows (playbook_actions → alerts → incidents → logs)."""
    if not log_ids:
        return {"deleted_logs": 0, "deleted_incidents": 0, "deleted_alerts": 0, "deleted_actions": 0}

    incident_ids = [
        r[0] for r in db.query(Incident.id).filter(Incident.trigger_log_id.in_(log_ids)).all()
    ]

    deleted_actions = 0
    deleted_alerts = 0
    deleted_incidents = 0

    if incident_ids:
        deleted_actions = db.query(PlaybookAction).filter(
            PlaybookAction.incident_id.in_(incident_ids)
        ).delete(synchronize_session=False)

        deleted_alerts = db.query(Alert).filter(
            Alert.incident_id.in_(incident_ids)
        ).delete(synchronize_session=False)

        deleted_incidents = db.query(Incident).filter(
            Incident.id.in_(incident_ids)
        ).delete(synchronize_session=False)

    deleted_logs = db.query(Log).filter(Log.id.in_(log_ids)).delete(synchronize_session=False)
    db.commit()

    return {
        "deleted_logs": deleted_logs,
        "deleted_incidents": deleted_incidents,
        "deleted_alerts": deleted_alerts,
        "deleted_actions": deleted_actions,
    }


@router.delete("/{log_id}")
def delete_log(
    log_id: int,
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a single log and its linked incident chain."""
    log = db.query(Log).filter(Log.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    result = _cascade_delete_logs(db, [log_id])
    logger.info("User %s deleted log #%d", user.username, log_id)
    return result


class BulkDeleteRequest(BaseModel):
    source: Optional[str] = None
    before: Optional[datetime] = None
    all: Optional[bool] = False


@router.delete("")
def delete_logs_bulk(
    payload: BulkDeleteRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Bulk delete logs by source, date, or all."""
    q = db.query(Log.id)
    if not payload.all:
        if not payload.source and not payload.before:
            raise HTTPException(status_code=400, detail="Specify source, before, or all=true")
        if payload.source:
            q = q.filter(Log.source == payload.source)
        if payload.before:
            q = q.filter(Log.timestamp < payload.before)
    log_ids = [r[0] for r in q.all()]
    result = _cascade_delete_logs(db, log_ids)
    logger.info("User %s bulk-deleted %d logs (source=%s, before=%s, all=%s)",
                user.username, result["deleted_logs"], payload.source, payload.before, payload.all)
    return result


@router.post("/archive")
def archive_and_purge(
    user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Trigger archive_logs.py logic: archive old logs to gzip, then delete from DB."""
    import gzip, json
    from pathlib import Path
    from datetime import timezone, timedelta

    retain_hours = float(os.getenv("LOG_RETAIN_HOURS", "0.25"))
    archive_dir = Path(os.getenv("ARCHIVE_DIR", "/opt/soc-lab/logs/archive"))
    archive_dir.mkdir(parents=True, exist_ok=True)

    cutoff = datetime.now(timezone.utc) - timedelta(hours=retain_hours)
    rows = db.query(Log).filter(Log.timestamp < cutoff).order_by(Log.timestamp.asc()).all()

    if not rows:
        return {"archived": 0, "message": f"No logs older than {retain_hours}h to archive."}

    by_date = {}
    for row in rows:
        d = row.timestamp.strftime("%Y-%m-%d") if row.timestamp else "unknown"
        by_date.setdefault(d, []).append(_log_to_dict(row))

    archived_count = 0
    for date_str, log_list in by_date.items():
        archive_path = archive_dir / f"{date_str}.json.gz"
        existing = []
        if archive_path.exists():
            with gzip.open(archive_path, "rt") as f:
                existing = json.load(f)
        combined = existing + log_list
        with gzip.open(archive_path, "wt") as f:
            json.dump(combined, f, default=str)
        archived_count += len(log_list)

    log_ids = [row.id for row in rows]
    result = _cascade_delete_logs(db, log_ids)
    logger.info("User %s archived %d logs and purged from DB", user.username, archived_count)
    return {
        "archived": archived_count,
        "purged": result,
        "retain_hours": retain_hours,
    }


# ── Serialiser ──────────────────────────────────────────────────────────────

def _log_to_dict(log: Log) -> dict:
    return {
        "id":            log.id,
        "source":        log.source,
        "timestamp":     log.timestamp.isoformat() if log.timestamp else None,
        "log_level":     log.log_level,
        "message":       log.message,
        "ip_src":        log.ip_src,
        "ip_dst":        log.ip_dst,
        "user":          log.user,
        "event_type":    log.event_type,
        "anomaly_score": log.anomaly_score,
        "risk_score":    log.risk_score,
        "is_anomalous":  log.is_anomalous,
        "explanation":   log.explanation,
        "asset_id":      log.asset_id,
        "incident_id":   log.incident.id if log.incident else None,
    }
