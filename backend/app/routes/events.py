from __future__ import annotations

import json
import time

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from ..services import event_bus
from ..services.config import settings

router = APIRouter(prefix="/api/events", tags=["events"])


def _sse_stream():
    client = event_bus.get_client()
    pubsub = client.pubsub()
    pubsub.subscribe(settings.redis_pubsub_channel)
    try:
        while True:
            message = pubsub.get_message(timeout=1.0)
            if message and message.get("type") == "message":
                data = message.get("data")
                yield f"data: {data}\n\n"
            else:
                yield ": keep-alive\n\n"
            time.sleep(0.5)
    finally:
        pubsub.close()


@router.get("/stream")
async def stream_events():
    """
    Server-Sent Events endpoint for live incident/log updates.
    """
    if not settings.use_redis_streams:
        return StreamingResponse(iter(["data: {\"type\":\"disabled\"}\n\n"]), media_type="text/event-stream")
    return StreamingResponse(_sse_stream(), media_type="text/event-stream")
