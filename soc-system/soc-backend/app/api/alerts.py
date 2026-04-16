from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.db.models import Alert
from app.schemas.alert import AlertResponse

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/", response_model=List[AlertResponse])
async def list_alerts(limit: int = 100, db: AsyncSession = Depends(get_db)) -> List[AlertResponse]:
    result = await db.execute(select(Alert).order_by(Alert.last_seen.desc()).limit(limit))
    alerts = result.scalars().all()
    return [
        AlertResponse(
            id=alert.id,
            hostname=alert.hostname,
            event_id=alert.event_id,
            alert_type=alert.alert_type,
            message=alert.message,
            count=alert.count,
            first_seen=alert.first_seen,
            last_seen=alert.last_seen,
            is_active=alert.is_active,
            resolved_at=alert.resolved_at,
        )
        for alert in alerts
    ]
