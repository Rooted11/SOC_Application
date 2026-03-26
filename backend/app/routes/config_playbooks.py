from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..services.database import get_db, PlaybookDefinition, PlaybookExecutionHistory
from ..services.authz import require_permissions

router = APIRouter(prefix="/api/config/playbooks", tags=["config:playbooks"])


class PlaybookCreate(BaseModel):
    name: str
    description: str | None = ""
    enabled: bool = True
    triggers: list[dict] = []
    conditions: dict = {}
    actions: list[dict] = []
    requires_approval: bool = False


class PlaybookUpdate(BaseModel):
    description: str | None = None
    enabled: bool | None = None
    triggers: list[dict] | None = None
    conditions: dict | None = None
    actions: list[dict] | None = None
    requires_approval: bool | None = None


@router.get("", dependencies=[Depends(require_permissions(["config:*", "playbooks:write"]))])
def list_playbooks(db: Session = Depends(get_db)):
    pbs = db.query(PlaybookDefinition).order_by(PlaybookDefinition.created_at.desc()).all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "enabled": p.enabled,
            "requires_approval": p.requires_approval,
            "triggers": p.triggers,
            "actions": p.actions,
        }
        for p in pbs
    ]


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permissions(["config:*", "playbooks:write"]))])
def create_playbook(payload: PlaybookCreate, db: Session = Depends(get_db)):
    existing = db.query(PlaybookDefinition).filter(PlaybookDefinition.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Playbook name already exists")
    pb = PlaybookDefinition(
        name=payload.name,
        description=payload.description or "",
        enabled=payload.enabled,
        triggers=payload.triggers,
        conditions=payload.conditions,
        actions=payload.actions,
        requires_approval=payload.requires_approval,
    )
    db.add(pb)
    db.commit()
    return {"id": pb.id}


@router.patch("/{playbook_id}", dependencies=[Depends(require_permissions(["config:*", "playbooks:write"]))])
def update_playbook(playbook_id: int, payload: PlaybookUpdate, db: Session = Depends(get_db)):
    pb = db.query(PlaybookDefinition).filter(PlaybookDefinition.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
    if payload.description is not None:
        pb.description = payload.description
    if payload.enabled is not None:
        pb.enabled = payload.enabled
    if payload.triggers is not None:
        pb.triggers = payload.triggers
    if payload.conditions is not None:
        pb.conditions = payload.conditions
    if payload.actions is not None:
        pb.actions = payload.actions
    if payload.requires_approval is not None:
        pb.requires_approval = payload.requires_approval
    db.commit()
    return {"id": pb.id}


@router.get("/{playbook_id}/history", dependencies=[Depends(require_permissions(["view:*", "playbooks:write"]))])
def playbook_history(playbook_id: int, db: Session = Depends(get_db)):
    history = (
        db.query(PlaybookExecutionHistory)
        .filter(PlaybookExecutionHistory.playbook_id == playbook_id)
        .order_by(PlaybookExecutionHistory.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id": h.id,
            "status": h.status.value,
            "result": h.result,
            "incident_id": h.incident_id,
            "triggered_by": h.triggered_by,
            "created_at": h.created_at,
        }
        for h in history
    ]


@router.delete("/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_permissions(["config:*", "playbooks:write"]))])
def delete_playbook(playbook_id: int, db: Session = Depends(get_db)):
    pb = db.query(PlaybookDefinition).filter(PlaybookDefinition.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
    db.delete(pb)
    db.commit()
    return None
