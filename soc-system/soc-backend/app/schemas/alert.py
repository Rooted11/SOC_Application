from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class AlertResponse(BaseModel):
    id: int
    hostname: str
    event_id: int
    alert_type: str
    message: str
    count: int
    first_seen: datetime
    last_seen: datetime
    is_active: bool
    resolved_at: Optional[datetime]


class AlertCreate(BaseModel):
    hostname: str
    event_id: int
    alert_type: str
    message: str
    count: int
