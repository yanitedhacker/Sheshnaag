"""Structured logging configuration.

Bridges stdlib ``logging`` and ``structlog`` so every log entry is emitted as a
single canonical JSON line when ``LOG_JSON`` (or production mode) is set, and
as a human-readable console line otherwise.

A request-scoped contextvar carries ``request_id``, ``tenant_id``, and ``actor``
into every log event without requiring callers to pass them explicitly.
"""

from __future__ import annotations

import logging
import os
import sys
from contextvars import ContextVar
from typing import Any, Mapping, MutableMapping, Optional

try:
    import structlog
except ImportError:  # pragma: no cover - depends on environment
    structlog = None


_LOG_CONTEXT: ContextVar[Mapping[str, Any]] = ContextVar("sheshnaag_log_context", default={})


def bind_log_context(**values: Any) -> None:
    """Merge ``values`` into the current request log context."""

    current: MutableMapping[str, Any] = dict(_LOG_CONTEXT.get() or {})
    for key, value in values.items():
        if value is None:
            current.pop(key, None)
        else:
            current[key] = value
    _LOG_CONTEXT.set(current)


def clear_log_context() -> None:
    _LOG_CONTEXT.set({})


def get_log_context() -> Mapping[str, Any]:
    return dict(_LOG_CONTEXT.get() or {})


def _merge_request_context(_logger: Any, _name: str, event_dict: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    for key, value in (_LOG_CONTEXT.get() or {}).items():
        event_dict.setdefault(key, value)
    return event_dict


def _resolve_json_mode(debug: bool) -> bool:
    raw = os.getenv("LOG_JSON")
    if raw is not None:
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    # Default: JSON logs in any non-development environment, console in dev.
    environment = os.getenv("ENVIRONMENT", "development").lower()
    if environment in {"production", "staging", "shared_server", "release_verification"}:
        return True
    return not debug


class _StructlogStdlibHandler(logging.Handler):
    """Stdlib log handler that funnels records through structlog."""

    def __init__(self) -> None:
        super().__init__()

    def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover - thin shim
        if structlog is None:
            return
        try:
            logger = structlog.get_logger(record.name)
            event = record.getMessage()
            kwargs: dict[str, Any] = {
                "logger_name": record.name,
                "module": record.module,
            }
            if record.exc_info:
                kwargs["exc_info"] = record.exc_info
            getattr(logger, record.levelname.lower(), logger.info)(event, **kwargs)
        except Exception:
            self.handleError(record)


def configure_logging(debug: bool = False) -> None:
    json_mode = _resolve_json_mode(debug)
    level = logging.DEBUG if debug else logging.INFO

    # Reset root handlers so re-configuration during tests does not duplicate
    # output. We attach exactly one stream handler.
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(handler)
    root.setLevel(level)

    if structlog is None:
        logging.getLogger(__name__).warning(
            "structlog is not installed; using stdlib logging only"
        )
        return

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        _merge_request_context,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if json_mode:
        processors.append(structlog.processors.JSONRenderer(sort_keys=True))
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=False))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )

    # Quiet noisy libraries unless explicitly debugging.
    for noisy in ("urllib3", "asyncio", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING if not debug else logging.INFO)


def get_logger(name: Optional[str] = None) -> Any:
    """Return a structlog logger when available, otherwise a stdlib logger."""

    if structlog is None:
        return logging.getLogger(name)
    return structlog.get_logger(name)


__all__ = [
    "bind_log_context",
    "clear_log_context",
    "configure_logging",
    "get_log_context",
    "get_logger",
]
