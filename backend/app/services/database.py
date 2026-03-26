"""
Database service — SQLAlchemy models and session management.
Tables: assets, logs, incidents, alerts, threat_indicators, playbook_actions
"""

import os
import hashlib
import secrets
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean,
    DateTime, Text, JSON, ForeignKey, Enum as SAEnum, UniqueConstraint
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import enum

from .config import settings

DATABASE_URL = os.getenv(
    "DATABASE_URL", "sqlite:///./ai_soc.db"
)

engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── Enums ──────────────────────────────────────────────────────────────────

class SeverityEnum(str, enum.Enum):
    critical = "critical"
    high     = "high"
    medium   = "medium"
    low      = "low"
    info     = "info"

class StatusEnum(str, enum.Enum):
    open           = "open"
    investigating  = "investigating"
    contained      = "contained"
    resolved       = "resolved"
    false_positive = "false_positive"

class PlaybookStatusEnum(str, enum.Enum):
    pending   = "pending"
    running   = "running"
    completed = "completed"
    failed    = "failed"


class DetectionRuleType(str, enum.Enum):
    threshold   = "threshold"
    rule        = "rule"
    ioc         = "ioc"
    correlation = "correlation"


class IntegrationType(str, enum.Enum):
    email     = "email"
    slack     = "slack"
    webhook   = "webhook"
    syslog    = "syslog"
    pagerduty = "pagerduty"


class NotificationChannelType(str, enum.Enum):
    email   = "email"
    slack   = "slack"
    webhook = "webhook"


class AuditAction(str, enum.Enum):
    create = "create"
    update = "update"
    delete = "delete"
    login  = "login"
    system = "system"


# ── Models ─────────────────────────────────────────────────────────────────

class Asset(Base):
    __tablename__ = "assets"
    id          = Column(Integer, primary_key=True, index=True)
    hostname    = Column(String(255), unique=True, index=True)
    ip_address  = Column(String(45), index=True)
    asset_type  = Column(String(50))          # server|workstation|network|user
    department  = Column(String(100))
    criticality = Column(String(20), default="medium")
    is_isolated = Column(Boolean, default=False)
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    logs      = relationship("Log",      back_populates="asset")
    incidents = relationship("Incident", back_populates="asset")


class Log(Base):
    __tablename__ = "logs"
    id            = Column(Integer, primary_key=True, index=True)
    source        = Column(String(100), index=True)   # syslog|firewall|auth|endpoint
    timestamp     = Column(DateTime, default=datetime.utcnow, index=True)
    log_level     = Column(String(20))
    message       = Column(Text)
    raw_data      = Column(JSON)
    ip_src        = Column(String(45), index=True)
    ip_dst        = Column(String(45))
    user          = Column(String(150))
    event_type    = Column(String(100))
    anomaly_score = Column(Float, default=0.0)
    risk_score    = Column(Float, default=0.0)
    is_anomalous  = Column(Boolean, default=False)
    explanation   = Column(Text)
    asset_id      = Column(Integer, ForeignKey("assets.id"), nullable=True)

    asset    = relationship("Asset",    back_populates="logs")
    incident = relationship("Incident", back_populates="trigger_log", uselist=False)


class Incident(Base):
    __tablename__ = "incidents"
    id                = Column(Integer, primary_key=True, index=True)
    title             = Column(String(300))
    description       = Column(Text)
    severity          = Column(SAEnum(SeverityEnum), default=SeverityEnum.medium)
    status            = Column(SAEnum(StatusEnum),   default=StatusEnum.open)
    risk_score        = Column(Float, default=0.0)
    ai_recommendation = Column(Text)
    ioc_matches       = Column(JSON, default=list)
    affected_assets   = Column(JSON, default=list)
    created_at        = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at        = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at       = Column(DateTime, nullable=True)
    trigger_log_id    = Column(Integer, ForeignKey("logs.id"), nullable=True)
    asset_id          = Column(Integer, ForeignKey("assets.id"), nullable=True)

    trigger_log      = relationship("Log",            back_populates="incident")
    asset            = relationship("Asset",          back_populates="incidents")
    alerts           = relationship("Alert",          back_populates="incident")
    playbook_actions = relationship("PlaybookAction", back_populates="incident")


class Alert(Base):
    __tablename__ = "alerts"
    id          = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"))
    channel     = Column(String(50))   # email|slack|pagerduty
    recipient   = Column(String(255))
    message     = Column(Text)
    sent_at     = Column(DateTime, default=datetime.utcnow)
    delivered   = Column(Boolean, default=True)

    incident = relationship("Incident", back_populates="alerts")


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id          = Column(Integer, primary_key=True, index=True)
    ioc_type    = Column(String(50), index=True)   # ip|domain|hash|url|email
    value       = Column(String(500), index=True)
    threat_type = Column(String(100))
    severity    = Column(String(20))
    confidence  = Column(Float, default=0.5)
    feed_source = Column(String(100))
    description = Column(Text)
    tags        = Column(JSON, default=list)
    first_seen  = Column(DateTime, default=datetime.utcnow)
    last_seen   = Column(DateTime, default=datetime.utcnow)
    is_active   = Column(Boolean, default=True)


class PlaybookAction(Base):
    __tablename__ = "playbook_actions"
    id          = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"))
    playbook    = Column(String(100))
    action      = Column(String(200))
    target      = Column(String(200))
    status      = Column(SAEnum(PlaybookStatusEnum), default=PlaybookStatusEnum.completed)
    result      = Column(Text)
    executed_at = Column(DateTime, default=datetime.utcnow)

    incident = relationship("Incident", back_populates="playbook_actions")


# â”€â”€ RBAC â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class Role(Base):
    __tablename__ = "roles"
    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String(50), unique=True, index=True)
    description = Column(Text, default="")
    built_in    = Column(Boolean, default=False)
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    permissions = relationship("RolePermission", cascade="all, delete-orphan", back_populates="role")
    users       = relationship("UserRole", cascade="all, delete-orphan", back_populates="role")


class RolePermission(Base):
    __tablename__ = "role_permissions"
    id       = Column(Integer, primary_key=True, index=True)
    role_id  = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"))
    perm     = Column(String(100), index=True)

    role = relationship("Role", back_populates="permissions")
    __table_args__ = (UniqueConstraint("role_id", "perm", name="uq_role_perm"),)


class User(Base):
    __tablename__ = "users"
    id             = Column(Integer, primary_key=True, index=True)
    username       = Column(String(150), unique=True, index=True)
    full_name      = Column(String(255))
    email          = Column(String(255))
    password_hash  = Column(String(255))
    password_salt  = Column(String(255))
    mfa_secret     = Column(String(255))
    is_active      = Column(Boolean, default=True)
    created_at     = Column(DateTime, default=datetime.utcnow)
    updated_at     = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    roles = relationship("UserRole", cascade="all, delete-orphan", back_populates="user")


class UserRole(Base):
    __tablename__ = "user_roles"
    id      = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"))

    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="users")
    __table_args__ = (UniqueConstraint("user_id", "role_id", name="uq_user_role"),)


# â”€â”€ Configurable detections â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id             = Column(Integer, primary_key=True, index=True)
    name           = Column(String(150), unique=True, index=True)
    description    = Column(Text, default="")
    rule_type      = Column(SAEnum(DetectionRuleType), default=DetectionRuleType.rule)
    enabled        = Column(Boolean, default=True)
    severity       = Column(String(20), default="medium")
    conditions     = Column(JSON, default=dict)      # arbitrary rule definition / thresholds
    suppression    = Column(JSON, default=dict)      # e.g. {"ips":["1.1.1.1"],"users":[]}
    tags           = Column(JSON, default=list)
    created_by     = Column(String(150))
    updated_by     = Column(String(150))
    created_at     = Column(DateTime, default=datetime.utcnow)
    updated_at     = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DetectionSuppression(Base):
    __tablename__ = "detection_suppressions"
    id         = Column(Integer, primary_key=True, index=True)
    rule_id    = Column(Integer, ForeignKey("detection_rules.id", ondelete="CASCADE"))
    matcher    = Column(String(255))
    expires_at = Column(DateTime, nullable=True)
    reason     = Column(Text, default="")


# â”€â”€ Playbooks (editable) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class PlaybookDefinition(Base):
    __tablename__ = "playbook_definitions"
    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String(150), unique=True, index=True)
    description = Column(Text, default="")
    enabled     = Column(Boolean, default=True)
    triggers    = Column(JSON, default=list)   # e.g., [{"event_type":"auth_failure","severity":">=high"}]
    conditions  = Column(JSON, default=dict)
    actions     = Column(JSON, default=list)   # array of action configs
    requires_approval = Column(Boolean, default=False)
    created_by  = Column(String(150))
    updated_by  = Column(String(150))
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class PlaybookExecutionHistory(Base):
    __tablename__ = "playbook_execution_history"
    id           = Column(Integer, primary_key=True, index=True)
    playbook_id  = Column(Integer, ForeignKey("playbook_definitions.id", ondelete="SET NULL"))
    incident_id  = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"))
    status       = Column(SAEnum(PlaybookStatusEnum), default=PlaybookStatusEnum.pending)
    result       = Column(Text)
    triggered_by = Column(String(150))
    created_at   = Column(DateTime, default=datetime.utcnow)


# â”€â”€ Integrations / Notifications â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class Integration(Base):
    __tablename__ = "integrations"
    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String(150), unique=True, index=True)
    type        = Column(SAEnum(IntegrationType))
    enabled     = Column(Boolean, default=True)
    config      = Column(JSON, default=dict)
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class NotificationChannel(Base):
    __tablename__ = "notification_channels"
    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String(150), unique=True, index=True)
    channel     = Column(SAEnum(NotificationChannelType))
    enabled     = Column(Boolean, default=True)
    config      = Column(JSON, default=dict)
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class OrgSettings(Base):
    __tablename__ = "org_settings"
    id                = Column(Integer, primary_key=True, default=1)
    org_name          = Column(String(255), default="Ataraxia")
    timezone          = Column(String(100), default="UTC")
    retention_days    = Column(Integer, default=30)
    allowed_ips       = Column(JSON, default=list)
    updated_at        = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AISettings(Base):
    __tablename__ = "ai_settings"
    id              = Column(Integer, primary_key=True, default=1)
    provider        = Column(String(50), default="anthropic")
    model           = Column(String(100), default="claude-3-haiku")
    enabled         = Column(Boolean, default=True)
    api_key_set     = Column(Boolean, default=False)
    temperature     = Column(Float, default=0.1)
    fallback_enabled= Column(Boolean, default=True)
    updated_at      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# â”€â”€ Threat Intel Feeds â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class ThreatFeed(Base):
    __tablename__ = "threat_feeds"
    id           = Column(Integer, primary_key=True, index=True)
    name         = Column(String(150), unique=True, index=True)
    url          = Column(String(500))
    enabled      = Column(Boolean, default=True)
    ttl_hours    = Column(Integer, default=24)
    confidence   = Column(Float, default=0.5)
    last_synced  = Column(DateTime, nullable=True)
    status       = Column(String(50), default="idle")
    last_error   = Column(Text, default="")
    created_at   = Column(DateTime, default=datetime.utcnow)
    updated_at   = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class FeedRun(Base):
    __tablename__ = "feed_runs"
    id          = Column(Integer, primary_key=True, index=True)
    feed_id     = Column(Integer, ForeignKey("threat_feeds.id", ondelete="CASCADE"))
    started_at  = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    status      = Column(String(50), default="running")
    items_ingested = Column(Integer, default=0)
    error       = Column(Text, default="")


# â”€â”€ Audit â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id           = Column(Integer, primary_key=True, index=True)
    actor        = Column(String(150))
    actor_roles  = Column(JSON, default=list)
    action       = Column(SAEnum(AuditAction))
    entity_type  = Column(String(100))
    entity_id    = Column(String(100))
    ip_address   = Column(String(64))
    details      = Column(JSON, default=dict)
    created_at   = Column(DateTime, default=datetime.utcnow, index=True)


# ── Alarms ──────────────────────────────────────────────────────────────────────

class Alarm(Base):
    __tablename__ = "alarms"
    id          = Column(Integer, primary_key=True, index=True)
    source      = Column(String(100))
    message     = Column(Text)
    severity    = Column(String(20), default="medium")
    status      = Column(String(20), default="open")  # open | acknowledged | cleared
    created_at  = Column(DateTime, default=datetime.utcnow, index=True)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(150), nullable=True)


# ── Helpers ────────────────────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables and seed demo assets and RBAC defaults."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _seed_roles_and_admin(db)
        _seed_settings(db)
        if db.query(Asset).count() == 0:
            db.add_all([
                Asset(hostname="web-server-01",  ip_address="10.0.1.10",   asset_type="server",      department="Engineering",  criticality="high"),
                Asset(hostname="db-server-01",   ip_address="10.0.1.20",   asset_type="server",      department="Engineering",  criticality="critical"),
                Asset(hostname="workstation-42", ip_address="10.0.2.42",   asset_type="workstation", department="Finance",      criticality="medium"),
                Asset(hostname="vpn-gateway",    ip_address="203.0.113.1", asset_type="network",     department="IT",           criticality="high"),
                Asset(hostname="mail-server-01", ip_address="10.0.1.30",   asset_type="server",      department="IT",           criticality="high"),
                Asset(hostname="dc-server-01",   ip_address="10.0.1.5",    asset_type="server",      department="IT",           criticality="critical"),
            ])
            db.commit()
    finally:
        db.close()


# â”€â”€ Seeding helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

ROLE_PRESETS = {
    "super_admin": [
        "*",
    ],
    "admin": [
        "admin:users", "admin:roles", "config:*", "view:audit", "view:metrics", "playbooks:write",
    ],
    "analyst": [
        "view:*", "incidents:write", "logs:ingest", "playbooks:run", "detections:write",
    ],
    "viewer": [
        "view:*",
    ],
}


def _hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    salt_bytes = bytes.fromhex(salt) if salt else secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 120000)
    return salt_bytes.hex(), derived.hex()


def _seed_roles_and_admin(db):
    # Create roles + permissions
    for role_name, perms in ROLE_PRESETS.items():
        role = db.query(Role).filter(Role.name == role_name).first()
        if not role:
            role = Role(name=role_name, description=f"Built-in {role_name} role", built_in=True)
            db.add(role)
            db.flush()
        existing_perms = {p.perm for p in role.permissions}
        for perm in perms:
            if perm not in existing_perms:
                db.add(RolePermission(role_id=role.id, perm=perm))
    db.commit()

    # Seed super admin user if none exists
    if db.query(User).count() == 0:
        salt, pwd_hash = _hash_password(settings.auth_password)
        user = User(
            username=settings.auth_username,
            full_name="SOC Super Admin",
            email="admin@example.com",
            password_hash=pwd_hash,
            password_salt=salt,
            is_active=True,
        )
        db.add(user)
        db.flush()
        sa_role = db.query(Role).filter(Role.name == "super_admin").first()
        if sa_role:
            db.add(UserRole(user_id=user.id, role_id=sa_role.id))
        db.commit()


def _seed_settings(db):
    if db.query(OrgSettings).count() == 0:
        db.add(OrgSettings(org_name="Ataraxia"))
    if db.query(AISettings).count() == 0:
        db.add(AISettings(enabled=True))
    db.commit()
