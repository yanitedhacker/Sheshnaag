"""Unit tests for the V4 structured-log context helpers."""

from __future__ import annotations

from app.core.logging import bind_log_context, clear_log_context, get_log_context


def test_bind_and_clear_round_trip():
    bind_log_context(request_id="abc", path="/api/v4/runs", method="POST")
    ctx = get_log_context()
    assert ctx["request_id"] == "abc"
    assert ctx["path"] == "/api/v4/runs"
    assert ctx["method"] == "POST"
    clear_log_context()
    assert get_log_context() == {}


def test_bind_clears_keys_on_none():
    bind_log_context(request_id="abc", tenant_id=42)
    assert get_log_context()["tenant_id"] == 42
    bind_log_context(tenant_id=None)
    ctx = get_log_context()
    assert "tenant_id" not in ctx
    assert ctx["request_id"] == "abc"
    clear_log_context()
