"""Tests for the OpenTelemetry bootstrap contract."""

from app.core.observability import _otlp_trace_endpoint


def test_otlp_trace_endpoint_appends_trace_path_to_base_url():
    assert _otlp_trace_endpoint("http://otel-collector:4318") == (
        "http://otel-collector:4318/v1/traces"
    )


def test_otlp_trace_endpoint_does_not_duplicate_explicit_trace_path():
    assert _otlp_trace_endpoint("http://otel-collector:4318/v1/traces") == (
        "http://otel-collector:4318/v1/traces"
    )
