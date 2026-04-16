import json
from typing import List

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.db.models import LogEntry
from app.detectors.failed_login import detect_failed_logins
from app.schemas.log import LogPayload, LogResponse

router = APIRouter(prefix="/logs", tags=["logs"])


@router.post("/", status_code=status.HTTP_201_CREATED)
async def ingest_log(payload: LogPayload, db: AsyncSession = Depends(get_db)) -> dict:
    entry = LogEntry(
        event_id=payload.event_id,
        message=payload.message,
        hostname=payload.hostname,
        source_ip=str(payload.source_ip),
        timestamp=payload.timestamp,
        log_name=payload.log_name,
        level=payload.level,
        user=payload.user,
        details=json.dumps(payload.details) if payload.details else None,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    await detect_failed_logins(db, entry)
    return {"status": "accepted", "id": entry.id}


@router.get("/", response_model=List[LogResponse])
async def list_logs(limit: int = Query(100, ge=1, le=500), db: AsyncSession = Depends(get_db)) -> List[LogResponse]:
    result = await db.execute(
        select(LogEntry).order_by(LogEntry.timestamp.desc()).limit(limit)
    )
    entries = result.scalars().all()

    return [
        LogResponse(
            id=entry.id,
            event_id=entry.event_id,
            message=entry.message,
            hostname=entry.hostname,
            source_ip=entry.source_ip,
            timestamp=entry.timestamp,
            log_name=entry.log_name or "",
            level=entry.level,
            user=entry.user,
        )
        for entry in entries
    ]
