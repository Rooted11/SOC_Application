from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..services.database import get_db, DetectionRule, DetectionRuleType
from ..services.authz import require_permissions

router = APIRouter(prefix="/api/config/detections", tags=["config:detections"])


class DetectionCreate(BaseModel):
    name: str
    description: str | None = ""
    rule_type: DetectionRuleType = DetectionRuleType.rule
    enabled: bool = True
    severity: str = "medium"
    conditions: dict = {}
    suppression: dict = {}
    tags: list[str] = []


class DetectionUpdate(BaseModel):
    description: str | None = None
    enabled: bool | None = None
    severity: str | None = None
    conditions: dict | None = None
    suppression: dict | None = None
    tags: list[str] | None = None


@router.get("", dependencies=[Depends(require_permissions(["config:*", "detections:write"]))])
def list_detections(db: Session = Depends(get_db)):
    rules = db.query(DetectionRule).order_by(DetectionRule.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "rule_type": r.rule_type.value,
            "enabled": r.enabled,
            "severity": r.severity,
            "conditions": r.conditions,
            "suppression": r.suppression,
            "tags": r.tags,
        }
        for r in rules
    ]


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permissions(["config:*", "detections:write"]))])
def create_detection(payload: DetectionCreate, db: Session = Depends(get_db)):
    existing = db.query(DetectionRule).filter(DetectionRule.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Detection name already exists")
    rule = DetectionRule(
        name=payload.name,
        description=payload.description or "",
        rule_type=payload.rule_type,
        enabled=payload.enabled,
        severity=payload.severity,
        conditions=payload.conditions,
        suppression=payload.suppression,
        tags=payload.tags,
    )
    db.add(rule)
    db.commit()
    return {"id": rule.id}


@router.patch("/{rule_id}", dependencies=[Depends(require_permissions(["config:*", "detections:write"]))])
def update_detection(rule_id: int, payload: DetectionUpdate, db: Session = Depends(get_db)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    if payload.description is not None:
        rule.description = payload.description
    if payload.enabled is not None:
        rule.enabled = payload.enabled
    if payload.severity is not None:
        rule.severity = payload.severity
    if payload.conditions is not None:
        rule.conditions = payload.conditions
    if payload.suppression is not None:
        rule.suppression = payload.suppression
    if payload.tags is not None:
        rule.tags = payload.tags
    db.commit()
    return {"id": rule.id}


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_permissions(["config:*", "detections:write"]))])
def delete_detection(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    db.delete(rule)
    db.commit()
    return None
