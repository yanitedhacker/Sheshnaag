"""OpenTelemetry bootstrap.

Optional. The OTLP exporter is wired only when ``OTEL_EXPORTER_OTLP_ENDPOINT``
or ``OTEL_ENABLED=true`` is set, and we soft-fail when the SDK is missing so
local dev does not require the dependency.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)

_INSTRUMENTED = False


def _truthy(value: Optional[str]) -> bool:
    return bool(value) and value.strip().lower() in {"1", "true", "yes", "on"}


def otel_enabled() -> bool:
    if _truthy(os.getenv("OTEL_ENABLED")):
        return True
    return bool(os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))


def configure_telemetry(app: Any = None, *, service_name: Optional[str] = None) -> bool:
    """Wire OpenTelemetry tracing if an exporter endpoint is configured.

    Returns ``True`` when OTel was successfully initialised, ``False`` if the
    feature was disabled or the optional dependency was missing. Idempotent
    across calls so re-import in tests is harmless.
    """

    global _INSTRUMENTED
    if _INSTRUMENTED:
        return True
    if not otel_enabled():
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:  # pragma: no cover - optional dependency missing
        logger.warning(
            "OTEL endpoint configured but opentelemetry SDK not installed; "
            "telemetry disabled (install opentelemetry-sdk + opentelemetry-exporter-otlp)."
        )
        return False

    resource = Resource.create(
        {
            SERVICE_NAME: service_name or os.getenv("OTEL_SERVICE_NAME", "sheshnaag"),
            "deployment.environment": os.getenv("ENVIRONMENT", "development"),
            "service.version": os.getenv("APP_VERSION", "0.1.0"),
        }
    )
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter()
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    if app is not None:
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

            FastAPIInstrumentor.instrument_app(app)
        except Exception as exc:  # pragma: no cover - optional
            logger.warning("Failed to instrument FastAPI: %s", exc)

    for instrumentor_path in (
        ("opentelemetry.instrumentation.sqlalchemy", "SQLAlchemyInstrumentor"),
        ("opentelemetry.instrumentation.redis", "RedisInstrumentor"),
        ("opentelemetry.instrumentation.requests", "RequestsInstrumentor"),
    ):
        module_name, attr = instrumentor_path
        try:
            module = __import__(module_name, fromlist=[attr])
            getattr(module, attr)().instrument()
        except Exception:  # pragma: no cover - optional
            continue

    _INSTRUMENTED = True
    logger.info("OpenTelemetry tracing enabled")
    return True


__all__ = ["configure_telemetry", "otel_enabled"]
