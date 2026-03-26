"""
In-memory rate limiting helpers.

Suitable for a single-instance deployment baseline. For horizontally-scaled
production deployments, replace this with a shared backend such as Redis.
"""

from __future__ import annotations

import math
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after_seconds: int


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, *, limit: int, window_seconds: int) -> RateLimitResult:
        now = time.monotonic()
        with self._lock:
            bucket = self._events[key]
            self._prune(bucket, now=now, window_seconds=window_seconds)

            if len(bucket) >= limit:
                oldest = bucket[0]
                retry_after = max(1, math.ceil(window_seconds - (now - oldest)))
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    retry_after_seconds=retry_after,
                )

            bucket.append(now)
            remaining = max(0, limit - len(bucket))
            return RateLimitResult(
                allowed=True,
                remaining=remaining,
                retry_after_seconds=0,
            )

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)

    @staticmethod
    def _prune(bucket: deque[float], *, now: float, window_seconds: int) -> None:
        threshold = now - window_seconds
        while bucket and bucket[0] <= threshold:
            bucket.popleft()


api_rate_limiter = InMemoryRateLimiter()
login_rate_limiter = InMemoryRateLimiter()
