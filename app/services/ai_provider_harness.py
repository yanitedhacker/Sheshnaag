"""AI provider harness for Sheshnaag V4.

Dispatches analyst requests to one of six native provider adapters. Public API
is kept compatible with V3 callers:

    harness = AIProviderHarness()
    providers = harness.list_providers()           # catalog w/ health
    result    = harness.run(                       # grounded draft
        provider_key="anthropic",
        capability="draft_report_sections",
        prompt="...",
        grounding={"items": [...]},
    )

Safety note: V3's `BLOCKED_PROMPT_PATTERNS` regex has been removed. Safety now
flows through `app.services.capability_policy` (see
`docs/SHESHNAAG_V4_CAPABILITY_POLICY.md`). The grounding validator is
preserved because grounding is a *correctness* requirement, not a safety one.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional

from app.services.ai_adapters import (
    AnthropicAdapter,
    AzureOpenAIAdapter,
    BedrockAdapter,
    GeminiAdapter,
    LocalOpenAICompatAdapter,
    NativeAIAdapter,
    OpenAIAdapter,
    collect_stream,
)


logger = logging.getLogger(__name__)

SUPPORTED_CAPABILITIES = {
    "summarize_evidence",
    "cluster_iocs",
    "draft_hypotheses",
    "generate_detection_candidates",
    "draft_mitigation",
    "draft_report_sections",
    "variant_diff_review",
}

# Back-compat aliases from V3 provider keys to V4 native adapter keys. V3
# callers using the old keys still work; a deprecation warning is logged once
# per unique alias per process.
DEPRECATED_PROVIDER_ALIASES: Dict[str, str] = {
    "goodbear-cli": "ollama",
    "openai-api": "openai",
    "anthropic-api": "anthropic",
}

_ALIAS_WARNED: set = set()


def _grounded_fallback_markdown(
    *,
    display_name: str,
    model_label: str,
    capability: str,
    prompt: str,
    grounding: Dict[str, Any],
    execution_status: str,
    execution_error: Optional[str] = None,
) -> str:
    items = grounding.get("items") or []
    lines = [
        f"## {display_name} draft",
        "",
        f"- Capability: `{capability}`",
        f"- Model: `{model_label}`",
        f"- Grounding items: `{len(items)}`",
        f"- Execution status: `{execution_status}`",
        "",
        "### Analyst prompt",
        prompt.strip(),
        "",
        "### Grounded output",
        "This draft is restricted to supplied artifacts and must be reviewed before promotion.",
    ]
    if execution_error:
        lines.extend(["", "### Provider note", execution_error.strip()])
    if items:
        lines.append("")
        lines.append("### Grounding summary")
        for item in items[:8]:
            if isinstance(item, dict):
                label = item.get("label") or item.get("kind") or "context"
                summary = item.get("summary") or item.get("value") or item
                lines.append(f"- {label}: {str(summary)[:160]}")
            else:
                lines.append(f"- {str(item)[:160]}")
    return "\n".join(lines)


class AIProviderHarness:
    """Catalog and execute grounded AI draft runs across V4 native adapters."""

    def __init__(self, adapters: Optional[Dict[str, NativeAIAdapter]] = None) -> None:
        if adapters is None:
            adapters = self._default_adapters()
        self._adapters: Dict[str, NativeAIAdapter] = adapters

    # -- construction ---------------------------------------------------------

    @staticmethod
    def _default_adapters() -> Dict[str, NativeAIAdapter]:
        return {
            "anthropic": AnthropicAdapter(),
            "openai": OpenAIAdapter(),
            "gemini": GeminiAdapter(),
            "azure-openai": AzureOpenAIAdapter(),
            "bedrock": BedrockAdapter(),
            "ollama": LocalOpenAICompatAdapter(),
        }

    # -- catalog --------------------------------------------------------------

    def list_providers(self) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        for key, adapter in self._adapters.items():
            try:
                health = adapter.health()
            except Exception as exc:  # pragma: no cover - defensive
                logger.exception("health probe failed for %s", key)
                health = {"status": "error", "healthy": False, "error": str(exc)}
            model_label = getattr(adapter, "model_label", health.get("model") or "unknown")
            # provider_mode retained for back-compat with AISession.provider_mode
            # (a V3 column). Local providers report "local"; others report "api".
            provider_mode = getattr(adapter, "provider_mode", None) or (
                "local" if key in {"ollama", "vllm"} else "api"
            )
            entries.append(
                {
                    "provider_key": key,
                    "provider_mode": provider_mode,
                    "display_name": adapter.display_name,
                    "capabilities": list(adapter.capabilities),
                    "healthy": bool(health.get("healthy")),
                    "status": health.get("status", "unknown"),
                    "health": health,
                    "model_label": model_label,
                }
            )
        return entries

    # -- lookup ---------------------------------------------------------------

    def get_adapter(self, provider_key: str) -> NativeAIAdapter:
        resolved = self._resolve_key(provider_key)
        if resolved not in self._adapters:
            raise ValueError(f"Unsupported AI provider '{provider_key}'.")
        return self._adapters[resolved]

    # Back-compat alias: the V3 API called it `get_provider`.
    def get_provider(self, provider_key: str) -> NativeAIAdapter:
        return self.get_adapter(provider_key)

    def _resolve_key(self, provider_key: str) -> str:
        if provider_key in self._adapters:
            return provider_key
        if provider_key in DEPRECATED_PROVIDER_ALIASES:
            target = DEPRECATED_PROVIDER_ALIASES[provider_key]
            if provider_key not in _ALIAS_WARNED:
                logger.warning(
                    "provider_key '%s' is deprecated; use '%s'",
                    provider_key,
                    target,
                )
                _ALIAS_WARNED.add(provider_key)
            return target
        return provider_key

    # -- validation -----------------------------------------------------------

    def validate_grounding(self, grounding: Dict[str, Any]) -> None:
        items = (grounding or {}).get("items") or []
        if not items:
            raise ValueError("Grounding evidence is required for V4 AI sessions.")
        if len(items) > 25:
            raise ValueError("Grounding payload is too large for a reviewed V4 AI session.")

    # -- run ------------------------------------------------------------------

    def run(
        self,
        *,
        provider_key: str,
        capability: str,
        prompt: str,
        grounding: Dict[str, Any],
        tools: Optional[List[Dict[str, Any]]] = None,
        cache_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        if capability not in SUPPORTED_CAPABILITIES:
            raise ValueError(f"Unsupported AI capability '{capability}'.")
        if not (prompt or "").strip():
            raise ValueError("Prompt is required.")
        self.validate_grounding(grounding)

        adapter = self.get_adapter(provider_key)
        if capability not in adapter.capabilities:
            raise ValueError(
                f"Provider '{provider_key}' does not support capability '{capability}'."
            )

        digest = hashlib.sha256(
            json.dumps(
                {"prompt": prompt, "grounding": grounding, "capability": capability},
                sort_keys=True,
                default=str,
            ).encode("utf-8")
        ).hexdigest()

        started = time.monotonic()
        aggregated = collect_stream(
            adapter.stream(
                capability=capability,
                prompt=prompt,
                grounding=grounding,
                tools=tools,
                cache_key=cache_key or digest[:16],
            )
        )
        duration_ms = int((time.monotonic() - started) * 1000)

        health = {}
        try:
            health = adapter.health()
        except Exception:  # pragma: no cover - defensive
            health = {"status": "unknown", "healthy": False}

        healthy = bool(health.get("healthy"))
        errors = aggregated["errors"]
        execution_status = "completed" if aggregated["stop_reason"] != "error" and not errors else (
            "unconfigured" if not healthy else "error"
        )
        provider_error = "; ".join(errors) if errors else None

        output_markdown = aggregated["text"].strip()
        if not output_markdown:
            output_markdown = _grounded_fallback_markdown(
                display_name=adapter.display_name,
                model_label=getattr(adapter, "model_label", "unknown"),
                capability=capability,
                prompt=prompt,
                grounding=grounding,
                execution_status=execution_status
                if execution_status != "completed"
                else "completed_empty",
                execution_error=provider_error,
            )

        execution = {
            "status": (
                "available"
                if execution_status == "completed"
                else ("unconfigured" if not healthy else "degraded")
            ),
            "healthy": execution_status == "completed",
            "stop_reason": aggregated["stop_reason"],
            "duration_ms": duration_ms,
            "usage": aggregated["usage"],
            "errors": errors,
            "metadata": aggregated.get("metadata") or {},
        }

        resolved_key = self._resolve_key(provider_key)
        provider_entry = {
            "provider_key": resolved_key,
            "provider_mode": getattr(adapter, "provider_mode", None) or (
                "local" if resolved_key in {"ollama", "vllm"} else "api"
            ),
            "display_name": adapter.display_name,
            "capabilities": list(adapter.capabilities),
            "healthy": healthy,
            "status": health.get("status", "unknown"),
            "health": health,
            "model_label": getattr(adapter, "model_label", "unknown"),
        }

        return {
            "provider": provider_entry,
            "grounding_digest": digest,
            "output_markdown": output_markdown,
            "output_payload": {
                "capability": capability,
                "grounding_count": len(grounding.get("items") or []),
                "draft_only": True,
                "execution_status": execution_status,
                "execution_error": provider_error,
                "tool_uses": aggregated["tool_uses"],
                "stop_reason": aggregated["stop_reason"],
            },
            "execution": execution,
        }
