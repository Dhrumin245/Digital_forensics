"""
Rate limiting for the public verification portal (US-13 / misuse case MC-07).

Why this exists
---------------
GET /verify/{hash} needs no login, so anyone can call it. Without a limit, an
attacker could hammer it to enumerate which hashes exist in the system. This
module caps requests per client IP: VERIFY_RATE_LIMIT_PER_MINUTE and
VERIFY_RATE_LIMIT_PER_HOUR (see core/config.py).

How it works
------------
Primary store: Redis, using a fixed-window counter per IP.
    INCR  rl:verify:<ip>:m:<minute-bucket>   -> count for this minute
    EXPIRE the key on first hit so old windows clean themselves up.
Redis is shared by every API pod, so the limit holds across replicas.

Fallback: if Redis is unreachable we fall back to an in-process sliding window.
This "fails open" on purpose — a Redis outage must never take the verification
portal down (lawyers and judges depend on it). The trade-off is that during a
Redis outage the limit is per-pod rather than global; that is logged.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

from core.config import settings

log = logging.getLogger(__name__)

_redis = None                                   # lazily created client
_local: dict[str, deque[float]] = defaultdict(deque)   # in-process fallback


def reset_local_state() -> None:
    """Clear the in-process fallback counters (used by tests)."""
    _local.clear()


async def _get_redis():
    global _redis
    if _redis is None:
        import redis.asyncio as aioredis
        _redis = aioredis.from_url(
            settings.REDIS_URL,
            socket_connect_timeout=0.5,
            socket_timeout=0.5,
        )
    return _redis


def _allow_local(key: str, limit: int, window_s: int) -> bool:
    """Sliding-window check held in this process's memory."""
    now = time.monotonic()
    hits = _local[key]
    while hits and now - hits[0] > window_s:
        hits.popleft()
    if len(hits) >= limit:
        return False
    hits.append(now)
    return True


async def _allow(key: str, limit: int, window_s: int) -> bool:
    """Return True if this request is within the limit for `key`."""
    try:
        r = await _get_redis()
        bucket = int(time.time() // window_s)
        redis_key = f"rl:{key}:{bucket}"
        count = await r.incr(redis_key)
        if count == 1:
            await r.expire(redis_key, window_s)
        return count <= limit
    except Exception as exc:                     # Redis down, timeout, etc.
        log.warning("Redis rate limiter unavailable (%s) — using in-process fallback", exc)
        return _allow_local(key, limit, window_s)


async def verify_rate_limit(request: Request) -> None:
    """
    FastAPI dependency: raise HTTP 429 if this IP has exceeded the verify limits.
    Attach with `dependencies=[Depends(verify_rate_limit)]` on the route.
    """
    ip = request.client.host if request.client else "unknown"

    within_minute = await _allow(f"verify:{ip}:m", settings.VERIFY_RATE_LIMIT_PER_MINUTE, 60)
    within_hour   = await _allow(f"verify:{ip}:h", settings.VERIFY_RATE_LIMIT_PER_HOUR, 3600)

    if not (within_minute and within_hour):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please wait before verifying more hashes.",
            headers={"Retry-After": "60"},
        )
