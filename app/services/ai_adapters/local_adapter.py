"""Local OpenAI-compatible adapter for Ollama or vLLM air-gapped deployments."""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import httpx

from app.services.ai_adapters.openai_adapter import OpenAIAdapter


class LocalOpenAICompatAdapter(OpenAIAdapter):
    """OpenAI-compatible endpoint. Defaults to Ollama, can point at vLLM.

    Discovery order for base URL:
      1. explicit base_url argument
      2. OLLAMA_HOST env (appended with /v1)
      3. VLLM_HOST env (appended with /v1)
      4. http://localhost:11434/v1 (Ollama default)
    """

    provider_key = "ollama"
    display_name = "Local (Ollama / vLLM)"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        model: str | None = None,
        http_client: httpx.Client | None = None,
        api_key: str | None = None,
    ) -> None:
        resolved_base = base_url
        if not resolved_base:
            ollama = os.getenv("OLLAMA_HOST")
            vllm = os.getenv("VLLM_HOST")
            if ollama:
                resolved_base = ollama.rstrip("/") + "/v1"
            elif vllm:
                resolved_base = vllm.rstrip("/") + "/v1"
            else:
                resolved_base = "http://localhost:11434/v1"

        resolved_model = model or os.getenv("LOCAL_AI_MODEL") or "llama3.1:8b"
        # Ollama ignores the key; vLLM may want one. OPENAI_API_KEY fallback for
        # gateways that proxy to a local vLLM.
        resolved_key = api_key or os.getenv("LOCAL_AI_API_KEY") or "local-noauth"

        super().__init__(
            api_key=resolved_key,
            base_url=resolved_base,
            model=resolved_model,
            http_client=http_client,
        )

    def health(self) -> dict[str, Any]:
        # The local provider is always considered "configured"; reachability is
        # probed lazily at the base URL.
        probe = {"status": "available", "healthy": True, "missing_configuration": []}
        probe["model"] = self.model_label
        probe["base_url"] = self._base_url
        client = self._http or httpx.Client(timeout=httpx.Timeout(3.0, connect=2.0))
        close_client = self._http is None
        try:
            try:
                # OpenAI-compatible /models endpoint is supported by both Ollama
                # (as /v1/models) and vLLM.
                resp = client.get(f"{self._base_url}/models")
                probe["reachable"] = 200 <= resp.status_code < 500
            except httpx.HTTPError:
                probe["reachable"] = False
                probe["healthy"] = False
                probe["status"] = "unreachable"
        finally:
            if close_client:
                client.close()
        return probe

    def stream(
        self,
        *,
        capability: str,
        prompt: str,
        grounding: dict[str, Any],
        tools: list[dict[str, Any]] | None = None,
        cache_key: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        # OpenAI-compatible; inherit the parent streaming implementation.
        yield from super().stream(
            capability=capability,
            prompt=prompt,
            grounding=grounding,
            tools=tools,
            cache_key=cache_key,
        )
