from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..services.database import get_db, Integration, IntegrationType
from ..services.authz import require_permissions

router = APIRouter(prefix="/api/config/integrations", tags=["config:integrations"])


class IntegrationCreate(BaseModel):
    name: str
    type: IntegrationType
    enabled: bool = True
    config: dict = {}


class IntegrationUpdate(BaseModel):
    enabled: bool | None = None
    config: dict | None = None


@router.get("", dependencies=[Depends(require_permissions(["config:*"]))])
def list_integrations(db: Session = Depends(get_db)):
    items = db.query(Integration).all()
    return [
        {
            "id": i.id,
            "name": i.name,
            "type": i.type.value,
            "enabled": i.enabled,
            "config": i.config,
        }
        for i in items
    ]


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permissions(["config:*"]))])
def create_integration(payload: IntegrationCreate, db: Session = Depends(get_db)):
    existing = db.query(Integration).filter(Integration.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Integration name exists")
    item = Integration(
        name=payload.name,
        type=payload.type,
        enabled=payload.enabled,
        config=payload.config,
    )
    db.add(item)
    db.commit()
    return {"id": item.id}


@router.patch("/{integration_id}", dependencies=[Depends(require_permissions(["config:*"]))])
def update_integration(integration_id: int, payload: IntegrationUpdate, db: Session = Depends(get_db)):
    item = db.query(Integration).filter(Integration.id == integration_id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")
    if payload.enabled is not None:
        item.enabled = payload.enabled
    if payload.config is not None:
        item.config = payload.config
    db.commit()
    return {"id": item.id}


@router.delete("/{integration_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_permissions(["config:*"]))])
def delete_integration(integration_id: int, db: Session = Depends(get_db)):
    item = db.query(Integration).filter(Integration.id == integration_id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")
    db.delete(item)
    db.commit()
    return None
