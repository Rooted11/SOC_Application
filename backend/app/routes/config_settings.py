from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..services.database import get_db, OrgSettings, AISettings
from ..services.authz import require_permissions

router = APIRouter(prefix="/api/config/settings", tags=["config:settings"])


class OrgSettingsUpdate(BaseModel):
    org_name: str | None = None
    timezone: str | None = None
    retention_days: int | None = None
    allowed_ips: list[str] | None = None


class AISettingsUpdate(BaseModel):
    provider: str | None = None
    model: str | None = None
    enabled: bool | None = None
    temperature: float | None = None
    fallback_enabled: bool | None = None


@router.get("", dependencies=[Depends(require_permissions(["config:*"]))])
def get_settings(db: Session = Depends(get_db)):
    org = db.query(OrgSettings).first()
    ai = db.query(AISettings).first()
    return {
        "org": {
            "org_name": org.org_name if org else "Ataraxia",
            "timezone": org.timezone if org else "UTC",
            "retention_days": org.retention_days if org else 30,
            "allowed_ips": org.allowed_ips if org else [],
        },
        "ai": {
            "provider": ai.provider if ai else "anthropic",
            "model": ai.model if ai else "claude-3-haiku",
            "enabled": ai.enabled if ai else True,
            "temperature": ai.temperature if ai else 0.1,
            "fallback_enabled": ai.fallback_enabled if ai else True,
        },
    }


@router.patch("/org", dependencies=[Depends(require_permissions(["config:*"]))])
def update_org_settings(payload: OrgSettingsUpdate, db: Session = Depends(get_db)):
    org = db.query(OrgSettings).first()
    if not org:
        org = OrgSettings()
        db.add(org)
        db.flush()
    if payload.org_name is not None:
        org.org_name = payload.org_name
    if payload.timezone is not None:
        org.timezone = payload.timezone
    if payload.retention_days is not None:
        org.retention_days = payload.retention_days
    if payload.allowed_ips is not None:
        org.allowed_ips = payload.allowed_ips
    db.commit()
    return {"org_name": org.org_name}


@router.patch("/ai", dependencies=[Depends(require_permissions(["config:*"]))])
def update_ai_settings(payload: AISettingsUpdate, db: Session = Depends(get_db)):
    ai = db.query(AISettings).first()
    if not ai:
        ai = AISettings()
        db.add(ai)
        db.flush()
    if payload.provider is not None:
        ai.provider = payload.provider
    if payload.model is not None:
        ai.model = payload.model
    if payload.enabled is not None:
        ai.enabled = payload.enabled
    if payload.temperature is not None:
        ai.temperature = payload.temperature
    if payload.fallback_enabled is not None:
        ai.fallback_enabled = payload.fallback_enabled
    db.commit()
    return {"provider": ai.provider, "model": ai.model, "enabled": ai.enabled}
