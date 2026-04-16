from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.alerts import router as alerts_router
from app.api.logs import router as logs_router
from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.db.session import init_db

logger = get_logger(__name__)

app = FastAPI(
    title="Enterprise SOC Collector",
    description="Lightweight log ingestion service for Windows agents",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(logs_router)
app.include_router(alerts_router)


@app.middleware("http")
async def request_logger(request: Request, call_next):
    logger.info("Incoming %s %s", request.method, request.url)
    try:
        response = await call_next(request)
        logger.info("Responded %s %s %s", response.status_code, request.method, request.url)
        return response
    except Exception as exc:
        logger.exception("Unhandled exception for %s %s", request.method, request.url)
        raise


@app.on_event("startup")
async def startup_event():
    configure_logging()
    await init_db()
    logger.info("SOC backend ready on %s:%s", settings.host, settings.port)


@app.get("/health")
def health_check():
    return {"status": "ok", "mode": "production"}
