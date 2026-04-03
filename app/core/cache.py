"""Lightweight Redis cache helpers used by v2 services."""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

import redis

from app.core.config import settings

logger = logging.getLogger(__name__)

_redis_client: Optional[redis.Redis] = None


def get_redis_client() -> Optional[redis.Redis]:
    """Return a Redis client when available, otherwise None."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    try:
        _redis_client = redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1)
        _redis_client.ping()
        return _redis_client
    except Exception as exc:  # pragma: no cover - depends on runtime infra
        logger.debug("Redis unavailable for cache usage: %s", exc)
        _redis_client = None
        return None


def cache_get_json(key: str) -> Optional[Any]:
    """Fetch cached JSON payload."""
    client = get_redis_client()
    if client is None:
        return None

    try:
        raw = client.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as exc:  # pragma: no cover - defensive cache path
        logger.debug("Cache get failed for %s: %s", key, exc)
        return None


def cache_set_json(key: str, value: Any, ex: int = 300) -> None:
    """Store JSON payload with TTL."""
    client = get_redis_client()
    if client is None:
        return

    try:
        client.set(key, json.dumps(value), ex=ex)
    except Exception as exc:  # pragma: no cover - defensive cache path
        logger.debug("Cache set failed for %s: %s", key, exc)
