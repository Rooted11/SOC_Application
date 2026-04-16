"""
FastAPI application entry point for the AI-Powered SOC backend.
"""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.routes.auth import router as auth_router
from app.services.config import settings, validate_settings
from app.services.database import init_db
from app.services.rate_limit import api_rate_limiter
from app.services.security import get_current_user, get_agent_or_user, get_request_client_ip
from app.services.threat_intel import threat_intel
from app.services.database import SessionLocal
from app.routes.logs import router as logs_router
from app.routes.incidents import router as incidents_router
from app.routes.ai import router as ai_router
from app.routes.events import router as events_router
from app.routes.admin_users import router as admin_users_router
from app.routes.admin_roles import router as admin_roles_router
from app.routes.config_detections import router as detections_router
from app.routes.config_playbooks import router as playbooks_router
from app.routes.config_integrations import router as integrations_router
from app.routes.config_notifications import router as notifications_router
from app.routes.config_settings import router as settings_router
from app.routes.system import router as system_router
from app.routes.audit import router as audit_router
from app.routes.alarms import router as alarms_router

from app.logging_config import get_logger

logger = get_logger(__name__)
_UNLIMITED_PATHS = {"/api/auth/status", "/api/auth/login", "/health", "/"}

validate_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle handler."""
    logger.info("Initialising database tables and seed data...")
    init_db()

    if settings.seed_demo_data:
        logger.info("Loading threat intelligence feeds...")
        db = SessionLocal()
        try:
            threat_intel.load_from_file(db)
            threat_intel.fetch_live_feed(db)
        finally:
            db.close()

    logger.info("Ataraxia backend ready.")
    yield
    logger.info("Ataraxia backend shutting down.")


app = FastAPI(
    title="AI-Powered Security Operations Center",
    description=(
        "Automated incident response, anomaly detection, threat intelligence "
        "correlation, and decision-support for SOC analysts."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.enable_api_docs else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.enable_api_docs else None,
)

if settings.allowed_hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.middleware("http")
async def add_security_headers(request, call_next):
    if (
        settings.rate_limit_enabled
        and request.url.path.startswith("/api/")
        and request.url.path not in _UNLIMITED_PATHS
    ):
        rate_limit = api_rate_limiter.check(
            f"api:{get_request_client_ip(request)}",
            limit=settings.api_rate_limit_requests,
            window_seconds=settings.api_rate_limit_window_seconds,
        )
        if not rate_limit.allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please retry later."},
                headers={"Retry-After": str(rate_limit.retry_after_seconds)},
            )

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if settings.rate_limit_enabled and request.url.path.startswith("/api/"):
        response.headers["X-RateLimit-Limit"] = str(settings.api_rate_limit_requests)
        response.headers["X-RateLimit-Window"] = str(settings.api_rate_limit_window_seconds)
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
    return response


app.include_router(auth_router)
app.include_router(logs_router)
app.include_router(incidents_router, dependencies=[Depends(get_current_user)])
app.include_router(ai_router, dependencies=[Depends(get_current_user)])
app.include_router(events_router, dependencies=[Depends(get_current_user)])
app.include_router(admin_users_router)
app.include_router(admin_roles_router)
app.include_router(detections_router)
app.include_router(playbooks_router)
app.include_router(integrations_router)
app.include_router(notifications_router)
app.include_router(settings_router)
app.include_router(system_router)
app.include_router(audit_router)
app.include_router(alarms_router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "ataraxia-backend"}


@app.get("/")
def root():
    return {
        "message": "Ataraxia API is running. Visit /docs for the interactive API explorer."
    }
