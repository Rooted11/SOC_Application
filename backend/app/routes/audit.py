from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..services.database import get_db, AuditLog
from ..services.authz import require_permissions

router = APIRouter(prefix="/api/audit/logs", tags=["audit"])


@router.get("", dependencies=[Depends(require_permissions(["view:audit", "config:*"]))])
def list_audit_logs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .offset(skip)
        .limit(min(limit, 500))
        .all()
    )
    return [
        {
            "id": log.id,
            "actor": log.actor,
            "actor_roles": log.actor_roles,
            "action": log.action.value if log.action else None,
            "entity_type": log.entity_type,
            "entity_id": log.entity_id,
            "details": log.details,
            "created_at": log.created_at,
        }
        for log in logs
    ]
