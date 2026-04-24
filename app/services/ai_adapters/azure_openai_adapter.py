"""Native Azure OpenAI adapter. Wire shape == OpenAI; auth via api-key header."""

from __future__ import annotations

import os
from typing import Any, Dict, Iterator, List, Optional

import httpx

from app.services.ai_adapters.openai_adapter import OpenAIAdapter


DEFAULT_API_VERSION = "2024-08-01-preview"


class AzureOpenAIAdapter(OpenAIAdapter):
    """Azure-flavored OpenAI. Reuses OpenAI SSE parsing; swaps auth + URL."""

    provider_key = "azure-openai"
    display_name = "Azure OpenAI"

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        deployment: Optional[str] = None,
        api_version: Optional[str] = None,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        resolved_key = api_key or os.getenv("AZURE_OPENAI_API_KEY")
        resolved_endpoint = (endpoint or os.getenv("AZURE_OPENAI_ENDPOINT") or "").rstrip("/")
        resolved_deployment = (
            deployment
            or os.getenv("AZURE_OPENAI_DEPLOYMENT")
            or os.getenv("AZURE_OPENAI_MODEL")
            or "gpt-4o"
        )
        resolved_version = (
            api_version or os.getenv("AZURE_OPENAI_API_VERSION") or DEFAULT_API_VERSION
        )

        # Fake a base_url that OpenAIAdapter will stream from; our override of
        # stream() replaces the URL entirely, so this value is cosmetic.
        super().__init__(
            api_key=resolved_key or "placeholder",
            base_url=resolved_endpoint or "https://placeholder.openai.azure.com",
            model=resolved_deployment,
            http_client=http_client,
        )
        self._real_api_key = resolved_key
        self._endpoint = resolved_endpoint
        self._deployment = resolved_deployment
        self._api_version = resolved_version

    def health(self) -> Dict[str, Any]:
        missing: List[str] = []
        if not self._real_api_key:
            missing.append("AZURE_OPENAI_API_KEY")
        if not self._endpoint:
            missing.append("AZURE_OPENAI_ENDPOINT")
        return {
            "status": "available" if not missing else "unconfigured",
            "healthy": not missing,
            "model": self._deployment,
            "endpoint": self._endpoint or None,
            "api_version": self._api_version,
            "missing_configuration": missing,
        }

    def stream(
        self,
        *,
        capability: str,
        prompt: str,
        grounding: Dict[str, Any],
        tools: Optional[List[Dict[str, Any]]] = None,
        cache_key: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        if not self._real_api_key or not self._endpoint:
            yield {"type": "error", "error": "Azure OpenAI not configured", "recoverable": False}
            yield {"type": "message_stop", "stop_reason": "error", "usage": {}}
            return

        body = self._build_body(capability=capability, prompt=prompt, grounding=grounding, tools=tools)
        if cache_key:
            body["user"] = str(cache_key)[:128]

        url = (
            f"{self._endpoint}/openai/deployments/{self._deployment}/chat/completions"
            f"?api-version={self._api_version}"
        )
        headers = {
            "api-key": self._real_api_key,
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        }

        client = self._http or httpx.Client(timeout=httpx.Timeout(60.0, connect=10.0))
        close_client = self._http is None
        try:
            try:
                with client.stream("POST", url, headers=headers, json=body) as resp:
                    if resp.status_code >= 400:
                        text = resp.read().decode("utf-8", errors="replace")
                        yield {"type": "error", "error": f"HTTP {resp.status_code}: {text[:500]}", "recoverable": False}
                        yield {"type": "message_stop", "stop_reason": "error", "usage": {}}
                        return
                    yield from self._parse_sse(resp.iter_lines())
            except httpx.HTTPError as exc:
                yield {"type": "error", "error": f"transport error: {exc}", "recoverable": True}
                yield {"type": "message_stop", "stop_reason": "error", "usage": {}}
        finally:
            if close_client:
                client.close()
