"""In-process sliding-window rate limiter per integration.

For single-instance deployments. For multi-instance, move the deques
to Redis. Default: 60 evaluate calls / 60s per integration, configurable
via RATE_LIMIT_PER_MINUTE. Opt-out with RATE_LIMIT_ENABLED=false.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException

from .auth import Principal

_WINDOW_SECONDS = 60.0

_buckets: dict[str, deque[float]] = defaultdict(deque)
_lock = Lock()


def _current_limit() -> int:
    return int(os.environ.get("RATE_LIMIT_PER_MINUTE", "60"))


def _enabled() -> bool:
    return os.environ.get("RATE_LIMIT_ENABLED", "true").lower() not in ("0", "false", "no")


def reset() -> None:
    """For tests."""
    with _lock:
        _buckets.clear()


def check_and_consume(principal: Principal, *, limit_override: int | None = None) -> None:
    if not _enabled() or principal.integration_id in ("dev", "simulator"):
        return
    limit = limit_override if limit_override is not None else _current_limit()
    now = time.monotonic()
    key = principal.integration_id
    with _lock:
        q = _buckets[key]
        # prune anything older than the window
        while q and now - q[0] > _WINDOW_SECONDS:
            q.popleft()
        if len(q) >= limit:
            oldest = q[0]
            retry_after = max(1, int(_WINDOW_SECONDS - (now - oldest)))
            raise HTTPException(
                status_code=429,
                detail=f"rate limit exceeded: {limit} requests/min for integration",
                headers={"Retry-After": str(retry_after)},
            )
        q.append(now)
