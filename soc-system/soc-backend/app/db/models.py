from datetime import datetime
from sqlalchemy import Column, DateTime, Integer, String, Text, Boolean

from app.db.base import Base


class LogEntry(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    event_id = Column(Integer, nullable=False, index=True)
    message = Column(Text, nullable=False)
    hostname = Column(String(255), nullable=False, index=True)
    source_ip = Column(String(64), nullable=False)
    log_name = Column(String(64), nullable=True)
    level = Column(String(32), nullable=True)
    user = Column(String(128), nullable=True)
    details = Column(Text, nullable=True)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), nullable=False, index=True)
    event_id = Column(Integer, nullable=False)
    alert_type = Column(String(128), nullable=False)
    message = Column(Text, nullable=False)
    count = Column(Integer, default=1)
    first_seen = Column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen = Column(DateTime(timezone=True), default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
