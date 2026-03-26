from __future__ import annotations

import json
import socket
from datetime import datetime
from typing import Iterable, Tuple, Any

import redis

from .config import settings


_client: redis.Redis | None = None


def get_client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    return _client


def _json_default(value: Any):
    """Ensure datetimes and other non-serializables can be dumped to JSON safely."""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def ensure_consumer_group() -> None:
    """Create the consumer group for the log stream if it doesn't already exist."""
    client = get_client()
    try:
        client.xgroup_create(
            name=settings.redis_stream_logs,
            groupname=settings.redis_consumer_group,
            id="0-0",
            mkstream=True,
        )
    except redis.ResponseError as exc:
        if "BUSYGROUP" in str(exc):
            return
        raise


def publish_logs(logs: Iterable[dict]) -> Tuple[int, list[str]]:
    """Publish logs to the Redis stream. Returns count and list of entry ids."""
    client = get_client()
    ids: list[str] = []
    for log in logs:
        entry_id = client.xadd(
            settings.redis_stream_logs,
            {"log": json.dumps(log, default=_json_default)},
        )
        ids.append(entry_id)
    return len(ids), ids


def publish_event(event: dict) -> None:
    """Publish a small event payload to the pub/sub channel for SSE."""
    client = get_client()
    client.publish(settings.redis_pubsub_channel, json.dumps(event, default=_json_default))


def get_consumer_name() -> str:
    return f"{settings.redis_consumer_name or 'worker'}-{socket.gethostname()}"
