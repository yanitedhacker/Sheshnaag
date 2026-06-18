"""Redis Streams backed event bus for live run and worker events."""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict
from collections.abc import Iterator
from typing import Any

import redis

from app.core.config import settings

logger = logging.getLogger(__name__)

_memory_lock = threading.Condition()
_memory_streams: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)


class EventBus:
    """Small Redis Streams wrapper with a dev/test in-memory fallback."""

    def __init__(self, *, redis_url: str | None = None, client: redis.Redis | None = None) -> None:
        self._redis_url = redis_url or settings.redis_url
        self._client = client
        self._redis_checked = client is not None

    @property
    def client(self) -> redis.Redis | None:
        if self._client is not None:
            return self._client
        if self._redis_checked:
            return None
        self._redis_checked = True
        try:
            self._client = redis.from_url(
                self._redis_url, socket_connect_timeout=1, socket_timeout=5
            )
            self._client.ping()
            return self._client
        except Exception as exc:  # pragma: no cover - depends on runtime infra
            logger.debug("Redis unavailable for EventBus; using in-memory fallback: %s", exc)
            self._client = None
            return None

    def publish(self, stream: str, event: dict[str, Any]) -> str:
        payload = dict(event)
        client = self.client
        if client is not None:
            entry_id = client.xadd(stream, {"data": json.dumps(payload, default=str)})
            return entry_id.decode("utf-8") if isinstance(entry_id, bytes) else str(entry_id)

        with _memory_lock:
            entry_id = f"{int(time.time() * 1000)}-{len(_memory_streams[stream])}"
            _memory_streams[stream].append((entry_id, payload))
            _memory_lock.notify_all()
            return entry_id

    def subscribe(
        self, stream: str, *, last_id: str = "$", block_ms: int = 5000
    ) -> Iterator[dict[str, Any]]:
        client = self.client
        if client is not None:
            current_id = last_id
            while True:
                rows = client.xread({stream: current_id}, block=block_ms, count=10)
                for _, messages in rows:
                    for entry_id, fields in messages:
                        current_id = (
                            entry_id.decode("utf-8")
                            if isinstance(entry_id, bytes)
                            else str(entry_id)
                        )
                        raw = fields.get(b"data") or fields.get("data")
                        if isinstance(raw, bytes):
                            raw = raw.decode("utf-8")
                        yield {"id": current_id, **json.loads(raw or "{}")}
            return

        current_index = len(_memory_streams[stream]) if last_id == "$" else 0
        while True:
            with _memory_lock:
                if current_index >= len(_memory_streams[stream]):
                    _memory_lock.wait(timeout=block_ms / 1000)
                rows = list(_memory_streams[stream][current_index:])
                current_index += len(rows)
            for entry_id, payload in rows:
                yield {"id": entry_id, **payload}


def run_event_stream(run_id: int) -> str:
    return f"sheshnaag:run:{run_id}:events"


def sandbox_return_stream(run_id: int) -> str:
    """Stream where workers publish signed-artifact return payloads."""
    return f"sheshnaag:sandbox:returns:{run_id}"


SANDBOX_WORK_STREAM = "sheshnaag:sandbox:work"


def build_tls_redis_client(
    redis_url: str,
    *,
    ssl_certfile: str,
    ssl_keyfile: str,
    ssl_ca_certs: str,
    socket_connect_timeout: int = 5,
    socket_timeout: int = 30,
) -> redis.Redis:
    """V5 W1b helper: redis-py client over a `rediss://` URL with mTLS.

    The control plane keeps using stock loopback `redis://` (lower
    overhead, no cert management). Sandbox workers connect via this
    helper using their enrolled cert as the TLS client identity.

    Raises ``ValueError`` for non-``rediss://`` URLs so a misconfigured
    worker fails loudly rather than silently downgrading to plaintext.
    """

    if not redis_url.startswith("rediss://"):
        raise ValueError(f"build_tls_redis_client requires rediss:// URL, got {redis_url!r}")
    return redis.from_url(
        redis_url,
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
        ssl_ca_certs=ssl_ca_certs,
        ssl_cert_reqs="required",
        socket_connect_timeout=socket_connect_timeout,
        socket_timeout=socket_timeout,
    )
