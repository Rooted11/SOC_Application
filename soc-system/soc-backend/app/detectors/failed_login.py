from datetime import timedelta, datetime
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models import Alert, LogEntry


async def detect_failed_logins(session: AsyncSession, entry: LogEntry) -> None:
    if entry.event_id != 4625:
        return

    window_start = entry.timestamp - timedelta(seconds=settings.failed_login_window_seconds)
    count_result = await session.execute(
        select(func.count(LogEntry.id)).where(
            LogEntry.hostname == entry.hostname,
            LogEntry.event_id == 4625,
            LogEntry.timestamp >= window_start,
        )
    )
    total_failures = count_result.scalar_one()

    if total_failures <= settings.failed_login_threshold:
        return

    existing = await session.scalar(
        select(Alert)
        .where(Alert.hostname == entry.hostname)
        .where(Alert.alert_type == "failed-login-bruteforce")
        .where(Alert.is_active.is_(True))
        .limit(1)
    )

    if existing:
        existing.count = total_failures
        existing.last_seen = entry.timestamp
        await session.commit()
        return

    alert = Alert(
        hostname=entry.hostname,
        event_id=entry.event_id,
        alert_type="failed-login-bruteforce",
        message=f"Detected {total_failures} failed logins within {settings.failed_login_window_seconds // 60} minutes.",
        count=total_failures,
        first_seen=entry.timestamp,
        last_seen=entry.timestamp,
        is_active=True,
    )
    session.add(alert)
    await session.commit()
