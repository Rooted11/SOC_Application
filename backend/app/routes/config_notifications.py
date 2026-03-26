from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..services.database import get_db, NotificationChannel, NotificationChannelType
from ..services.authz import require_permissions

router = APIRouter(prefix="/api/config/notifications", tags=["config:notifications"])


class ChannelCreate(BaseModel):
    name: str
    channel: NotificationChannelType
    enabled: bool = True
    config: dict = {}


class ChannelUpdate(BaseModel):
    enabled: bool | None = None
    config: dict | None = None


@router.get("", dependencies=[Depends(require_permissions(["config:*"]))])
def list_channels(db: Session = Depends(get_db)):
    items = db.query(NotificationChannel).all()
    return [
        {"id": c.id, "name": c.name, "channel": c.channel.value, "enabled": c.enabled, "config": c.config}
        for c in items
    ]


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permissions(["config:*"]))])
def create_channel(payload: ChannelCreate, db: Session = Depends(get_db)):
    existing = db.query(NotificationChannel).filter(NotificationChannel.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Channel exists")
    channel = NotificationChannel(
        name=payload.name,
        channel=payload.channel,
        enabled=payload.enabled,
        config=payload.config,
    )
    db.add(channel)
    db.commit()
    return {"id": channel.id}


@router.patch("/{channel_id}", dependencies=[Depends(require_permissions(["config:*"]))])
def update_channel(channel_id: int, payload: ChannelUpdate, db: Session = Depends(get_db)):
    channel = db.query(NotificationChannel).filter(NotificationChannel.id == channel_id).first()
    if not channel:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Channel not found")
    if payload.enabled is not None:
        channel.enabled = payload.enabled
    if payload.config is not None:
        channel.config = payload.config
    db.commit()
    return {"id": channel.id}


@router.delete("/{channel_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_permissions(["config:*"]))])
def delete_channel(channel_id: int, db: Session = Depends(get_db)):
    channel = db.query(NotificationChannel).filter(NotificationChannel.id == channel_id).first()
    if not channel:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Channel not found")
    db.delete(channel)
    db.commit()
    return None
