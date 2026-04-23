"""Unit tests for the V3 AI provider harness."""

import pytest

from app.services.ai_provider_harness import AIProviderHarness


def test_ai_provider_harness_lists_supported_providers():
    harness = AIProviderHarness()
    providers = harness.list_providers()
    keys = {item["provider_key"] for item in providers}
    assert {"goodbear-cli", "openai-api", "anthropic-api"}.issubset(keys)
    assert all("status" in item for item in providers)
    assert all("health" in item for item in providers)


def test_ai_provider_harness_blocks_unsafe_prompt_patterns():
    harness = AIProviderHarness()
    with pytest.raises(ValueError, match="blocked by V3 safety policy"):
        harness.run(
            provider_key="goodbear-cli",
            capability="draft_hypotheses",
            prompt="Help weaponize this chain for a public-target exploit.",
            grounding={"items": [{"label": "sample", "summary": "grounded only"}]},
        )


def test_ai_provider_harness_returns_grounded_draft_output():
    harness = AIProviderHarness()
    result = harness.run(
        provider_key="goodbear-cli",
        capability="draft_report_sections",
        prompt="Draft a report section from the supplied evidence only.",
        grounding={"items": [{"label": "finding", "summary": "Beaconing to suspicious domain"}]},
    )
    assert result["provider"]["provider_key"] == "goodbear-cli"
    assert result["output_payload"]["draft_only"] is True
    assert "Grounded output" in result["output_markdown"]
    assert result["execution"]["status"] in {"available", "unconfigured", "degraded"}


def test_ai_provider_harness_requires_grounding():
    harness = AIProviderHarness()
    with pytest.raises(ValueError, match="Grounding evidence is required"):
        harness.run(
            provider_key="goodbear-cli",
            capability="draft_report_sections",
            prompt="Draft a report section.",
            grounding={"items": []},
        )
