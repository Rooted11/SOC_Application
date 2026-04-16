"""
Application configuration and environment parsing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def _parse_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_csv(value: str | None, *, default: str = "") -> list[str]:
    raw = value if value is not None else default
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    environment: str
    use_redis_streams: bool
    redis_url: str
    redis_stream_logs: str
    redis_consumer_group: str
    redis_consumer_name: str | None
    redis_pubsub_channel: str
    log_retention_minutes: int
    auth_enabled: bool
    auth_username: str
    auth_password: str
    auth_token_secret: str
    auth_token_ttl_minutes: int
    auth_mfa_enabled: bool
    auth_totp_secret: str | None
    auth_totp_issuer: str
    rate_limit_enabled: bool
    api_rate_limit_requests: int
    api_rate_limit_window_seconds: int
    login_rate_limit_attempts: int
    login_rate_limit_window_seconds: int
    cors_origins: list[str]
    allowed_hosts: list[str]
    enable_api_docs: bool
    seed_demo_data: bool
    primary_asset_hostname: str
    primary_asset_ip: str
    ingest_token: str
    ai_auto_enabled: bool
    ai_model: str

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


def load_settings() -> Settings:
    environment = os.getenv("ENVIRONMENT", "development").strip().lower()
    is_production = environment == "production"
    auth_totp_secret = os.getenv("AUTH_TOTP_SECRET")

    return Settings(
        environment=environment,
        use_redis_streams=_parse_bool(
            os.getenv("USE_REDIS_STREAMS"),
            default=False,
        ),
        redis_url=os.getenv("REDIS_URL", "redis://redis:6379/0"),
        redis_stream_logs=os.getenv("REDIS_STREAM_LOGS", "logs"),
        redis_consumer_group=os.getenv("REDIS_CONSUMER_GROUP", "log-workers"),
        redis_consumer_name=os.getenv("REDIS_CONSUMER_NAME"),
        redis_pubsub_channel=os.getenv("REDIS_PUBSUB_CHANNEL", "events"),
        log_retention_minutes=int(os.getenv("LOG_RETENTION_MINUTES", "15")),
        auth_enabled=_parse_bool(
            os.getenv("AUTH_ENABLED"),
            default=is_production,
        ),
        auth_username=os.getenv("AUTH_USERNAME", "soc_operator"),
        auth_password=os.getenv("AUTH_PASSWORD", "soc_operator_local"),
        auth_token_secret=os.getenv("AUTH_TOKEN_SECRET", "local-dev-token-secret"),
        auth_token_ttl_minutes=int(os.getenv("AUTH_TOKEN_TTL_MINUTES", "480")),
        auth_mfa_enabled=_parse_bool(
            os.getenv("AUTH_MFA_ENABLED"),
            default=bool(auth_totp_secret),
        ),
        auth_totp_secret=auth_totp_secret,
        auth_totp_issuer=os.getenv("AUTH_TOTP_ISSUER", "Ataraxia"),
        rate_limit_enabled=_parse_bool(
            os.getenv("RATE_LIMIT_ENABLED"),
            default=is_production,
        ),
        api_rate_limit_requests=int(os.getenv("API_RATE_LIMIT_REQUESTS", "300")),
        api_rate_limit_window_seconds=int(os.getenv("API_RATE_LIMIT_WINDOW_SECONDS", "60")),
        login_rate_limit_attempts=int(os.getenv("LOGIN_RATE_LIMIT_ATTEMPTS", "5")),
        login_rate_limit_window_seconds=int(
            os.getenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "300")
        ),
        cors_origins=_parse_csv(
            os.getenv("CORS_ORIGINS"),
            default=(
                "http://localhost:3000,http://<WIN_HOST_IP>:3000,http://<SOC_UBUNTU_IP>:3000"
                if not is_production
                else ""
            ),
        ),
        allowed_hosts=_parse_csv(
            os.getenv("ALLOWED_HOSTS"),
            default=(
                "localhost,127.0.0.1,<WIN_HOST_IP>,<SOC_UBUNTU_IP>,testserver,backend"
                if not is_production
                else ""
            ),
        ),
        enable_api_docs=_parse_bool(
            os.getenv("ENABLE_API_DOCS"),
            default=not is_production,
        ),
        seed_demo_data=_parse_bool(
            os.getenv("SEED_DEMO_DATA"),
            default=True,
        ),
        primary_asset_hostname=os.getenv(
            "PRIMARY_ASSET_HOSTNAME",
            os.getenv("HOSTNAME", "soc-host"),
        ),
        primary_asset_ip=os.getenv(
            "PRIMARY_ASSET_IP",
            "<SOC_UBUNTU_IP>",
        ),
        ingest_token=os.getenv("INGEST_TOKEN", ""),
        ai_auto_enabled=_parse_bool(
            os.getenv("AI_AUTO_ENABLED"),
            default=False,
        ),
        ai_model=os.getenv("ANTHROPIC_MODEL") or os.getenv("CLAUDE_MODEL") or "claude-3-haiku",
    )


settings = load_settings()


def validate_settings() -> None:
    """Fail fast on obviously unsafe production configuration."""
    if not settings.is_production:
        return

    problems: list[str] = []
    placeholder_prefix = "replace-with-"

    if not settings.auth_enabled:
        problems.append("AUTH_ENABLED must be true in production.")
    if not os.getenv("AUTH_USERNAME"):
        problems.append("AUTH_USERNAME must be set in production.")
    if not os.getenv("AUTH_PASSWORD"):
        problems.append("AUTH_PASSWORD must be set in production.")
    if not os.getenv("AUTH_TOKEN_SECRET"):
        problems.append("AUTH_TOKEN_SECRET must be set in production.")
    if settings.auth_mfa_enabled and not settings.auth_totp_secret:
        problems.append("AUTH_TOTP_SECRET must be set when AUTH_MFA_ENABLED is true.")
    if not settings.allowed_hosts:
        problems.append("ALLOWED_HOSTS must list the public hostname(s) in production.")
    if settings.auth_password.startswith(placeholder_prefix):
        problems.append("AUTH_PASSWORD must be replaced with a real value in production.")
    if settings.auth_token_secret.startswith(placeholder_prefix):
        problems.append("AUTH_TOKEN_SECRET must be replaced with a real value in production.")
    if settings.auth_totp_secret and settings.auth_totp_secret.startswith(placeholder_prefix):
        problems.append("AUTH_TOTP_SECRET must be replaced with a real value in production.")
    if os.getenv("POSTGRES_PASSWORD", "").startswith(placeholder_prefix):
        problems.append("POSTGRES_PASSWORD must be replaced with a real value in production.")

    if problems:
        formatted = "\n".join(f"- {problem}" for problem in problems)
        raise RuntimeError(f"Unsafe production configuration:\n{formatted}")
