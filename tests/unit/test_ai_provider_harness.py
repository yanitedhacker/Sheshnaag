"""Unit tests for the V4 AI provider harness."""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional

import pytest

from app.services.ai_provider_harness import (
    AIProviderHarness,
    DEPRECATED_PROVIDER_ALIASES,
    SUPPORTED_CAPABILITIES,
)


class _StubAdapter:
    """Deterministic in-memory adapter that yields canned events."""

    def __init__(
        self,
        *,
        provider_key: str = "stub",
        display_name: str = "Stub",
        events: Optional[List[Dict[str, Any]]] = None,
        healthy: bool = True,
        model_label: str = "stub-1",
    ) -> None:
        self.provider_key = provider_key
        self.display_name = display_name
        self.model_label = model_label
        self.capabilities = sorted(SUPPORTED_CAPABILITIES)
        self._events = events if events is not None else [
            {"type": "message_start", "metadata": {"model": model_label}},
            {"type": "text_delta", "text": "Grounded output from stub."},
            {"type": "message_stop", "stop_reason": "end_turn", "usage": {"input_tokens": 3, "output_tokens": 4}},
        ]
        self._healthy = healthy

    def health(self) -> Dict[str, Any]:
        return {
            "status": "available" if self._healthy else "unconfigured",
            "healthy": self._healthy,
            "model": self.model_label,
            "missing_configuration": [] if self._healthy else ["STUB_KEY"],
        }

    def stream(self, **_: Any) -> Iterator[Dict[str, Any]]:
        yield from self._events


def _build_stub_harness(events: Optional[List[Dict[str, Any]]] = None) -> AIProviderHarness:
    adapters = {
        "anthropic": _StubAdapter(provider_key="anthropic", display_name="Anthropic", events=events),
        "openai": _StubAdapter(provider_key="openai", display_name="OpenAI", events=events),
        "gemini": _StubAdapter(provider_key="gemini", display_name="Gemini", events=events),
        "azure-openai": _StubAdapter(provider_key="azure-openai", display_name="Azure OpenAI", events=events),
        "bedrock": _StubAdapter(provider_key="bedrock", display_name="Bedrock", events=events),
        "ollama": _StubAdapter(provider_key="ollama", display_name="Local", events=events),
    }
    return AIProviderHarness(adapters=adapters)


def test_ai_provider_harness_lists_the_six_native_providers():
    harness = _build_stub_harness()
    providers = harness.list_providers()
    keys = {item["provider_key"] for item in providers}
    assert {"anthropic", "openai", "gemini", "azure-openai", "bedrock", "ollama"} == keys
    for item in providers:
        assert set(["provider_key", "display_name", "capabilities", "healthy", "status", "health", "model_label"]).issubset(item)


def test_ai_provider_harness_returns_grounded_draft_output():
    harness = _build_stub_harness()
    result = harness.run(
        provider_key="anthropic",
        capability="draft_report_sections",
        prompt="Draft a report section from the supplied evidence only.",
        grounding={"items": [{"label": "finding", "summary": "Beaconing to suspicious domain"}]},
    )
    assert result["provider"]["provider_key"] == "anthropic"
    assert result["output_payload"]["draft_only"] is True
    assert result["output_payload"]["stop_reason"] == "end_turn"
    assert "Grounded output" in result["output_markdown"]
    assert result["execution"]["status"] in {"available", "unconfigured", "degraded"}
    assert result["grounding_digest"]
    assert result["execution"]["usage"]["output_tokens"] == 4


def test_ai_provider_harness_requires_grounding():
    harness = _build_stub_harness()
    with pytest.raises(ValueError, match="Grounding evidence is required"):
        harness.run(
            provider_key="anthropic",
            capability="draft_report_sections",
            prompt="Draft a report section.",
            grounding={"items": []},
        )


def test_ai_provider_harness_rejects_unsupported_capability():
    harness = _build_stub_harness()
    with pytest.raises(ValueError, match="Unsupported AI capability"):
        harness.run(
            provider_key="anthropic",
            capability="not_a_real_capability",
            prompt="hi",
            grounding={"items": [{"label": "x", "summary": "y"}]},
        )


def test_ai_provider_harness_rejects_oversized_grounding():
    harness = _build_stub_harness()
    with pytest.raises(ValueError, match="too large"):
        harness.run(
            provider_key="anthropic",
            capability="draft_report_sections",
            prompt="hi",
            grounding={"items": [{"label": str(i)} for i in range(30)]},
        )


def test_ai_provider_harness_aliases_deprecated_keys():
    harness = _build_stub_harness()
    assert DEPRECATED_PROVIDER_ALIASES["goodbear-cli"] == "ollama"
    assert DEPRECATED_PROVIDER_ALIASES["openai-api"] == "openai"
    assert DEPRECATED_PROVIDER_ALIASES["anthropic-api"] == "anthropic"

    result = harness.run(
        provider_key="openai-api",
        capability="summarize_evidence",
        prompt="Summarize.",
        grounding={"items": [{"label": "x", "summary": "y"}]},
    )
    assert result["provider"]["provider_key"] == "openai"


def test_ai_provider_harness_emits_fallback_when_stream_empty():
    events = [
        {"type": "message_start", "metadata": {"model": "stub"}},
        {"type": "message_stop", "stop_reason": "end_turn", "usage": {}},
    ]
    harness = _build_stub_harness(events=events)
    result = harness.run(
        provider_key="anthropic",
        capability="draft_report_sections",
        prompt="Draft.",
        grounding={"items": [{"label": "x", "summary": "y"}]},
    )
    # No text emitted -> fallback markdown kicks in and mentions grounded output.
    assert "Grounded output" in result["output_markdown"]
