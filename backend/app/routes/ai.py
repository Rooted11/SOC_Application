"""
AI analysis routes — powered by Claude.
POST /api/ai/query       — on-demand Claude analysis for an incident
POST /api/ai/report/{id} — executive report generation
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..services.database import get_db, Incident, StatusEnum, SeverityEnum
from ..services.claude_service import analyze_incident, generate_executive_report
from ..services.threat_intel import threat_intel

router = APIRouter(prefix="/api/ai", tags=["ai"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class AIQueryRequest(BaseModel):
    incident_id: int
    query: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _incident_to_dict(inc: Incident, include_actions: bool = False) -> dict:
    d = {
        "id":              inc.id,
        "title":           inc.title,
        "description":     inc.description,
        "severity":        inc.severity.value if hasattr(inc.severity, "value") else inc.severity,
        "status":          inc.status.value   if hasattr(inc.status,   "value") else inc.status,
        "risk_score":      inc.risk_score,
        "affected_assets": inc.affected_assets or [],
        "ioc_matches":     inc.ioc_matches or [],
        "created_at":      inc.created_at.isoformat() if inc.created_at else None,
    }
    if inc.trigger_log:
        d["trigger_log"] = {
            "event_type": inc.trigger_log.event_type,
            "ip_src":     inc.trigger_log.ip_src,
            "ip_dst":     inc.trigger_log.ip_dst,
            "user":       inc.trigger_log.user,
            "timestamp":  (
                inc.trigger_log.timestamp.isoformat()
                if inc.trigger_log.timestamp else None
            ),
        }
    if include_actions:
        d["playbook_actions"] = [
            {"action": a.action, "status": a.status.value if hasattr(a.status, "value") else a.status}
            for a in (inc.playbook_actions or [])
        ]
    return d


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/query")
def ai_query(payload: AIQueryRequest, db: Session = Depends(get_db)):
    """Run a freeform Claude analysis query against an incident."""
    inc = db.query(Incident).filter(Incident.id == payload.incident_id).first()
    if not inc:
        raise HTTPException(404, "Incident not found")

    inc_dict   = _incident_to_dict(inc)
    ioc_detail = threat_intel.correlate_incident(db, inc)

    response = analyze_incident(inc_dict, payload.query, ioc_detail)
    return {"response": response, "incident_id": payload.incident_id}


@router.post("/report/{incident_id}")
def ai_report(incident_id: int, db: Session = Depends(get_db)):
    """Generate a Claude-authored executive incident report."""
    from sqlalchemy import func

    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(404, "Incident not found")

    open_count    = db.query(Incident).filter(
        Incident.status.in_([StatusEnum.open, StatusEnum.investigating])
    ).count()
    critical_open = db.query(Incident).filter(
        Incident.status.in_([StatusEnum.open, StatusEnum.investigating]),
        Incident.severity == SeverityEnum.critical,
    ).count()
    avg_risk = db.query(func.avg(Incident.risk_score)).scalar() or 0.0

    inc_dict  = _incident_to_dict(inc, include_actions=True)
    soc_stats = {
        "open_incidents": open_count,
        "critical_open":  critical_open,
        "avg_risk":       round(float(avg_risk), 1),
    }

    report = generate_executive_report(inc_dict, soc_stats)
    return {"report": report, "incident_id": incident_id}
