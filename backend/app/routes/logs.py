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

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..services.database import (
    get_db, Log, Asset, Incident, SeverityEnum, StatusEnum
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
