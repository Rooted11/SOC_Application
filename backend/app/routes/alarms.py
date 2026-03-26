from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..services.database import get_db, Alarm
from ..services.security import get_current_user, AuthenticatedUser

router = APIRouter(prefix="/api/alarms", tags=["alarms"], dependencies=[Depends(get_current_user)])


class AlarmCreate(BaseModel):
    source: str
    message: str
    severity: str = "medium"


@router.get("")
def list_alarms(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    alarms = (
        db.query(Alarm)
        .order_by(Alarm.created_at.desc())
        .offset(skip)
        .limit(min(limit, 500))
        .all()
    )
    return [
        {
            "id": a.id,
            "source": a.source,
            "message": a.message,
            "severity": a.severity,
            "status": a.status,
            "created_at": a.created_at,
            "acknowledged_at": a.acknowledged_at,
            "acknowledged_by": a.acknowledged_by,
        }
        for a in alarms
    ]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_alarm(payload: AlarmCreate, db: Session = Depends(get_db)):
    alarm = Alarm(
        source=payload.source,
        message=payload.message,
        severity=payload.severity,
        status="open",
    )
    db.add(alarm)
    db.commit()
    return {"id": alarm.id}


@router.post("/{alarm_id}/ack")
def ack_alarm(alarm_id: int, user: AuthenticatedUser = Depends(get_current_user), db: Session = Depends(get_db)):
    alarm = db.query(Alarm).filter(Alarm.id == alarm_id).first()
    if not alarm:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alarm not found")
    alarm.status = "acknowledged"
    alarm.acknowledged_at = datetime.utcnow()
    alarm.acknowledged_by = user.username
    db.commit()
    return {"id": alarm.id, "status": alarm.status}
