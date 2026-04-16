from datetime import datetime
from typing import Dict, Optional

from pydantic import BaseModel, Field, IPvAnyAddress


class LogPayload(BaseModel):
    event_id: int = Field(..., example=4625)
    message: str
    hostname: str
    source_ip: IPvAnyAddress
    timestamp: datetime
    log_name: str
    level: Optional[str]
    user: Optional[str]
    details: Dict[str, str] = Field(default_factory=dict)


class LogResponse(BaseModel):
    id: int
    event_id: int
    message: str
    hostname: str
    source_ip: str
    timestamp: datetime
    log_name: str
    level: Optional[str]
    user: Optional[str]
