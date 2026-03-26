"""
Incident management routes.
GET    /api/incidents              — list incidents
GET    /api/incidents/stats        — dashboard statistics
GET    /api/incidents/{id}         — incident detail
PATCH  /api/incidents/{id}         — update status / severity
POST   /api/incidents/{id}/respond — manually trigger a playbook
GET    /api/incidents/{id}/actions — playbook action audit log
GET    /api/threat-intel           — threat feed summary
POST   /api/threat-intel/refresh   — refresh threat feed
"""

from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, validator
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..services.database import (
    get_db, Incident, PlaybookAction, ThreatIndicator, Asset, Log,
    SeverityEnum, StatusEnum
)
from ..services.playbook import executor
from ..services.threat_intel import threat_intel

router = APIRouter(tags=["incidents"])
VALID_CRITICALITY = {"critical", "high", "medium", "low"}
VALID_TYPES = {"server", "workstation", "network", "user", "domain"}


# ── Pydantic schemas ──────────────────────────────────────────────────────

class IncidentUpdate(BaseModel):
    status:   Optional[str] = None
    severity: Optional[str] = None
    notes:    Optional[str] = None

class PlaybookRequest(BaseModel):
    playbook:  Optional[str] = None   # override auto-selection
    hostname:  Optional[str] = None
    ip:        Optional[str] = None
    username:  Optional[str] = None


class AssetCreate(BaseModel):
    hostname:    str
    ip_address:  str
    asset_type:  str
    department:  Optional[str] = None
    criticality: str = "medium"

    @validator("criticality")
    def validate_criticality(cls, v):
        v = v.lower()
        if v not in VALID_CRITICALITY:
            raise ValueError("criticality must be one of: critical, high, medium, low")
        return v

    @validator("asset_type")
    def validate_type(cls, v):
        v = v.lower()
        if v not in VALID_TYPES:
            raise ValueError("asset_type must be one of: server, workstation, network, user")
        return v

    @validator("hostname", "ip_address")
    def strip_value(cls, v):
        return v.strip()


class AssetUpdate(BaseModel):
    hostname:    Optional[str] = None
    ip_address:  Optional[str] = None
    asset_type:  Optional[str] = None
    department:  Optional[str] = None
    criticality: Optional[str] = None
    is_isolated: Optional[bool] = None

    @validator("criticality")
    def validate_criticality(cls, v):
        if v is None:
            return v
        v = v.lower()
        if v not in VALID_CRITICALITY:
            raise ValueError("criticality must be one of: critical, high, medium, low")
        return v

    @validator("asset_type")
    def validate_type(cls, v):
        if v is None:
            return v
        v = v.lower()
        if v not in VALID_TYPES:
            raise ValueError("asset_type must be one of: server, workstation, network, user")
        return v

    @validator("hostname", "ip_address")
    def strip_value(cls, v):
        return v.strip() if v else v


# ── Incidents ─────────────────────────────────────────────────────────────

@router.get("/api/incidents")
def list_incidents(
    status:   Optional[str]   = Query(None),
    severity: Optional[str]   = Query(None),
    min_risk: float            = Query(0.0),
    skip:     int              = Query(0, ge=0),
    limit:    int              = Query(50, le=200),
    db: Session = Depends(get_db),
):
    """Return paginated, filtered incident list ordered by creation date."""
    q = db.query(Incident)
    if status:
        try:
            q = q.filter(Incident.status == StatusEnum(status))
        except ValueError:
            raise HTTPException(400, f"Invalid status: {status}")
    if severity:
        try:
            q = q.filter(Incident.severity == SeverityEnum(severity))
        except ValueError:
            raise HTTPException(400, f"Invalid severity: {severity}")
    if min_risk > 0:
        q = q.filter(Incident.risk_score >= min_risk)
    total = q.count()
    rows  = q.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()
    return {
        "total":     total,
        "skip":      skip,
        "limit":     limit,
        "incidents": [_inc_to_dict(i) for i in rows],
    }


@router.get("/api/incidents/stats")
def incident_stats(db: Session = Depends(get_db)):
    """Dashboard statistics: counts by severity, status, and trend data."""
    total = db.query(Incident).count()
    by_sev = {
        sev.value: db.query(Incident)
                     .filter(Incident.severity == sev).count()
        for sev in SeverityEnum
    }
    by_status = {
        st.value: db.query(Incident)
                    .filter(Incident.status == st).count()
        for st in StatusEnum
    }
    avg_risk = db.query(func.avg(Incident.risk_score)).scalar() or 0.0

    # Trend: incidents per day for the last 7 days
    from datetime import timedelta
    trend = []
    today = datetime.utcnow().date()
    for i in range(6, -1, -1):
        day   = today - timedelta(days=i)
        count = (
            db.query(Incident)
            .filter(func.date(Incident.created_at) == day)
            .count()
        )
        trend.append({"date": day.isoformat(), "count": count})

    return {
        "total":          total,
        "by_severity":    by_sev,
        "by_status":      by_status,
        "avg_risk_score": round(float(avg_risk), 2),
        "trend_7d":       trend,
    }


@router.get("/api/overview")
def soc_overview(db: Session = Depends(get_db)):
    """High-signal summary for the SOC command center."""
    total_incidents = db.query(Incident).count()
    open_incidents = db.query(Incident).filter(
        Incident.status.in_([
            StatusEnum.open,
            StatusEnum.investigating,
            StatusEnum.contained,
        ])
    ).count()
    critical_open = db.query(Incident).filter(
        Incident.status.in_([StatusEnum.open, StatusEnum.investigating]),
        Incident.severity == SeverityEnum.critical,
    ).count()
    high_open = db.query(Incident).filter(
        Incident.status.in_([StatusEnum.open, StatusEnum.investigating]),
        Incident.severity == SeverityEnum.high,
    ).count()
    resolved_incidents = db.query(Incident).filter(
        Incident.status == StatusEnum.resolved
    ).count()
    contained_incidents = db.query(Incident).filter(
        Incident.status.in_([StatusEnum.contained, StatusEnum.resolved])
    ).count()
    incidents_with_actions = (
        db.query(func.count(func.distinct(PlaybookAction.incident_id))).scalar() or 0
    )
    avg_resolution_hours = (
        db.query(
            func.avg(
                func.extract("epoch", Incident.resolved_at - Incident.created_at) / 3600.0
            )
        )
        .filter(Incident.resolved_at.isnot(None))
        .scalar()
        or 0.0
    )

    total_assets = db.query(Asset).count()
    isolated_assets = db.query(Asset).filter(Asset.is_isolated == True).count()
    critical_assets = db.query(Asset).filter(Asset.criticality == "critical").count()

    active_iocs = db.query(ThreatIndicator).filter(ThreatIndicator.is_active == True).count()
    critical_iocs = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.severity.in_(["critical", "high"]),
    ).count()

    window_start = datetime.utcnow() - timedelta(hours=24)
    recent_logs = db.query(Log).filter(Log.timestamp >= window_start).count()
    recent_anomalies = db.query(Log).filter(
        Log.timestamp >= window_start,
        Log.is_anomalous == True,
    ).count()

    top_event_types = (
        db.query(Log.event_type, func.count(Log.id).label("count"))
        .group_by(Log.event_type)
        .order_by(func.count(Log.id).desc(), Log.event_type.asc())
        .limit(5)
        .all()
    )
    top_assets = (
        db.query(Asset.hostname, func.count(Incident.id).label("count"))
        .join(Incident, Incident.asset_id == Asset.id)
        .group_by(Asset.hostname)
        .order_by(func.count(Incident.id).desc(), Asset.hostname.asc())
        .limit(5)
        .all()
    )
    recent_incidents = (
        db.query(Incident)
        .order_by(Incident.created_at.desc())
        .limit(6)
        .all()
    )

    containment_rate = round(
        (contained_incidents / total_incidents) * 100, 1
    ) if total_incidents else 0.0
    automation_rate = round(
        (incidents_with_actions / total_incidents) * 100, 1
    ) if total_incidents else 0.0
    isolation_rate = round(
        (isolated_assets / total_assets) * 100, 1
    ) if total_assets else 0.0

    posture_score = 100
    posture_score -= min(critical_open * 12, 36)
    posture_score -= min(high_open * 5, 20)
    posture_score -= min(max(critical_iocs - 10, 0), 15)
    posture_score += min(int(automation_rate / 20), 5)
    posture_score = max(18, min(99, posture_score))

    return {
        "headline": {
            "posture_score": posture_score,
            "open_incidents": open_incidents,
            "critical_open": critical_open,
            "high_open": high_open,
            "recent_logs_24h": recent_logs,
            "recent_anomalies_24h": recent_anomalies,
        },
        "response": {
            "containment_rate_pct": containment_rate,
            "automation_rate_pct": automation_rate,
            "avg_resolution_hours": round(float(avg_resolution_hours), 2),
            "resolved_incidents": resolved_incidents,
        },
        "assets": {
            "total": total_assets,
            "critical": critical_assets,
            "isolated": isolated_assets,
            "isolation_rate_pct": isolation_rate,
        },
        "intel": {
            "active_iocs": active_iocs,
            "critical_iocs": critical_iocs,
        },
        "top_event_types": [
            {"event_type": event_type or "unknown", "count": count}
            for event_type, count in top_event_types
        ],
        "hot_assets": [
            {"hostname": hostname, "count": count}
            for hostname, count in top_assets
        ],
        "recent_incidents": [_inc_to_dict(incident) for incident in recent_incidents],
    }


@router.get("/api/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(404, "Incident not found")
    return _inc_to_dict(inc, detailed=True)


@router.patch("/api/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    db: Session = Depends(get_db),
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(404, "Incident not found")
    if payload.status:
        try:
            inc.status = StatusEnum(payload.status)
            if payload.status == "resolved":
                inc.resolved_at = datetime.utcnow()
        except ValueError:
            raise HTTPException(400, f"Invalid status: {payload.status}")
    if payload.severity:
        try:
            inc.severity = SeverityEnum(payload.severity)
        except ValueError:
            raise HTTPException(400, f"Invalid severity: {payload.severity}")
    if payload.notes:
        inc.description = (inc.description or "") + f"\n[Analyst note] {payload.notes}"
    inc.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(inc)
    return _inc_to_dict(inc)


@router.post("/api/incidents/{incident_id}/respond")
def trigger_playbook(
    incident_id: int,
    payload: PlaybookRequest,
    db: Session = Depends(get_db),
):
    """Manually trigger or override a playbook for an incident."""
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(404, "Incident not found")

    # Allow caller to provide context overrides
    if payload.hostname and not inc.affected_assets:
        inc.affected_assets = [payload.hostname]
    if payload.ip and inc.trigger_log:
        inc.trigger_log.ip_src = payload.ip
    if payload.username and inc.trigger_log:
        inc.trigger_log.user = payload.username
    db.commit()

    actions = executor.execute_for_incident(db, inc, payload.playbook)
    inc.status     = StatusEnum.investigating
    inc.updated_at = datetime.utcnow()
    db.commit()
    return {
        "incident_id": incident_id,
        "playbook":    payload.playbook or "auto",
        "actions":     [_action_to_dict(a) for a in actions],
    }


@router.get("/api/incidents/{incident_id}/actions")
def get_playbook_actions(incident_id: int, db: Session = Depends(get_db)):
    """Return the audit trail of all automated actions for an incident."""
    actions = (
        db.query(PlaybookAction)
        .filter(PlaybookAction.incident_id == incident_id)
        .order_by(PlaybookAction.executed_at.asc())
        .all()
    )
    return {"actions": [_action_to_dict(a) for a in actions]}


# ── Threat Intelligence ───────────────────────────────────────────────────

@router.get("/api/threat-intel")
def get_threat_intel(
    ioc_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit:    int            = Query(50, le=200),
    db: Session = Depends(get_db),
):
    """Return threat indicators and landscape summary."""
    q = db.query(ThreatIndicator).filter(ThreatIndicator.is_active == True)
    if ioc_type:
        q = q.filter(ThreatIndicator.ioc_type == ioc_type)
    if severity:
        q = q.filter(ThreatIndicator.severity == severity)
    indicators = q.order_by(ThreatIndicator.last_seen.desc()).limit(limit).all()
    summary    = threat_intel.generate_threat_summary(db)
    return {
        "summary":    summary,
        "indicators": [_ti_to_dict(t) for t in indicators],
    }


@router.post("/api/threat-intel/refresh")
def refresh_threat_feed(db: Session = Depends(get_db)):
    """Pull fresh IOCs from all configured feeds."""
    added_file = threat_intel.load_from_file(db)
    added_live = threat_intel.fetch_live_feed(db)
    return {
        "loaded_from_file": added_file,
        "fetched_live":     len(added_live),
        "total_added":      added_file + len(added_live),
    }


# ── Assets endpoint ───────────────────────────────────────────────────────

def _asset_to_dict(a: Asset) -> dict:
    return {
        "id":          a.id,
        "hostname":    a.hostname,
        "ip_address":  a.ip_address,
        "asset_type":  a.asset_type,
        "department":  a.department,
        "criticality": a.criticality,
        "is_isolated": a.is_isolated,
    }


@router.get("/api/assets")
def list_assets(db: Session = Depends(get_db)):
    assets = db.query(Asset).order_by(
        Asset.is_isolated.desc(),
        Asset.criticality.asc(),
        Asset.hostname.asc(),
    ).all()
    return {
        "summary": {
            "total": len(assets),
            "isolated": sum(1 for a in assets if a.is_isolated),
            "critical": sum(1 for a in assets if a.criticality == "critical"),
        },
        "assets": [_asset_to_dict(a) for a in assets],
    }


@router.post("/api/assets", status_code=201)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    if db.query(Asset).filter(Asset.hostname == payload.hostname).first():
        raise HTTPException(400, "Hostname already exists.")
    if db.query(Asset).filter(Asset.ip_address == payload.ip_address).first():
        raise HTTPException(400, "IP address already exists.")

    asset = Asset(
        hostname=payload.hostname,
        ip_address=payload.ip_address,
        asset_type=payload.asset_type,
        department=payload.department,
        criticality=payload.criticality,
        is_isolated=False,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return _asset_to_dict(asset)


@router.patch("/api/assets/{asset_id}")
def update_asset(asset_id: int, payload: AssetUpdate, db: Session = Depends(get_db)):
    asset = db.query(Asset).get(asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found.")

    if payload.hostname and payload.hostname != asset.hostname:
        if db.query(Asset).filter(Asset.hostname == payload.hostname).first():
            raise HTTPException(400, "Hostname already exists.")
        asset.hostname = payload.hostname

    if payload.ip_address and payload.ip_address != asset.ip_address:
        if db.query(Asset).filter(Asset.ip_address == payload.ip_address).first():
            raise HTTPException(400, "IP address already exists.")
        asset.ip_address = payload.ip_address

    if payload.asset_type:
        asset.asset_type = payload.asset_type
    if payload.department is not None:
        asset.department = payload.department
    if payload.criticality:
        asset.criticality = payload.criticality
    if payload.is_isolated is not None:
        asset.is_isolated = payload.is_isolated

    asset.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(asset)
    return _asset_to_dict(asset)


# ── Serialisers ───────────────────────────────────────────────────────────

def _inc_to_dict(inc: Incident, detailed: bool = False) -> dict:
    d = {
        "id":               inc.id,
        "title":            inc.title,
        "description":      inc.description,
        "severity":         inc.severity.value if hasattr(inc.severity, "value") else inc.severity,
        "status":           inc.status.value   if hasattr(inc.status,   "value") else inc.status,
        "risk_score":       inc.risk_score,
        "ioc_matches":      inc.ioc_matches or [],
        "affected_assets":  inc.affected_assets or [],
        "created_at":       inc.created_at.isoformat() if inc.created_at else None,
        "updated_at":       inc.updated_at.isoformat() if inc.updated_at else None,
        "resolved_at":      inc.resolved_at.isoformat() if inc.resolved_at else None,
        "ai_recommendation":inc.ai_recommendation,
    }
    if detailed:
        d["trigger_log"] = (
            {
                "id": inc.trigger_log.id,
                "timestamp": inc.trigger_log.timestamp.isoformat() if inc.trigger_log.timestamp else None,
                "source": inc.trigger_log.source,
                "event_type": inc.trigger_log.event_type,
                "message": inc.trigger_log.message,
                "ip_src": inc.trigger_log.ip_src,
                "ip_dst": inc.trigger_log.ip_dst,
                "user": inc.trigger_log.user,
            }
            if inc.trigger_log else None
        )
        d["alerts"]          = [
            {"channel": a.channel, "recipient": a.recipient, "sent_at": a.sent_at.isoformat()}
            for a in (inc.alerts or [])
        ]
        d["playbook_actions"] = [_action_to_dict(p) for p in (inc.playbook_actions or [])]
    return d


def _action_to_dict(pa: PlaybookAction) -> dict:
    return {
        "id":          pa.id,
        "playbook":    pa.playbook,
        "action":      pa.action,
        "target":      pa.target,
        "status":      pa.status.value if hasattr(pa.status, "value") else pa.status,
        "result":      pa.result,
        "executed_at": pa.executed_at.isoformat() if pa.executed_at else None,
    }


def _ti_to_dict(ti: ThreatIndicator) -> dict:
    return {
        "id":          ti.id,
        "ioc_type":    ti.ioc_type,
        "value":       ti.value,
        "threat_type": ti.threat_type,
        "severity":    ti.severity,
        "confidence":  ti.confidence,
        "feed_source": ti.feed_source,
        "description": ti.description,
        "tags":        ti.tags or [],
        "last_seen":   ti.last_seen.isoformat() if ti.last_seen else None,
    }
