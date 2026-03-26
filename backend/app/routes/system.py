from __future__ import annotations

import time
from fastapi import APIRouter, Depends

from ..services.authz import require_permissions
from ..services import event_bus, config

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/health", dependencies=[Depends(require_permissions(["view:metrics", "config:*"]))])
def system_health():
    redis_ok = False
    queue_depth = None
    try:
        client = event_bus.get_client()
        redis_ok = bool(client.ping())
        queue_depth = client.xlen(config.settings.redis_stream_logs)
    except Exception:
        redis_ok = False
    return {
        "redis": redis_ok,
        "queue_depth": queue_depth,
        "timestamp": int(time.time()),
    }
