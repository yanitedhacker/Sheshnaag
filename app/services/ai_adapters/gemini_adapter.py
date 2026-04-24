"""Native Google Generative Language (Gemini) streamGenerateContent adapter."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterator, List, Optional

import httpx

from app.services.ai_adapters.base import format_grounding_system_prompt


DEFAULT_MODEL = "gemini-1.5-pro-latest"
DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"


class GeminiAdapter:
    """Google Gemini streamGenerateContent with function-calling."""

    provider_key = "gemini"
    display_name = "Google Gemini"

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        self._api_key = api_key or os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        self._base_url = (base_url or os.getenv("GEMINI_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.model_label = model or os.getenv("GEMINI_MODEL") or DEFAULT_MODEL
        self._http = http_client
        self.capabilities = [
            "summarize_evidence",
            "cluster_iocs",
            "draft_hypotheses",
            "generate_detection_candidates",
            "draft_mitigation",
            "draft_report_sections",
            "variant_diff_review",
        ]

    def health(self) -> Dict[str, Any]:
        missing: List[str] = []
        if not self._api_key:
            missing.append("GOOGLE_API_KEY")
        return {
            "status": "available" if not missing else "unconfigured",
            "healthy": not missing,
            "model": self.model_label,
            "base_url": self._base_url,
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
        if not self._api_key:
            yield {"type": "error", "error": "GOOGLE_API_KEY not set", "recoverable": False}
            yield {"type": "message_stop", "stop_reason": "error", "usage": {}}
            return

        body = self._build_body(capability=capability, prompt=prompt, grounding=grounding, tools=tools)
        # Gemini SSE requires the alt=sse query param.
        url = (
            f"{self._base_url}/models/{self.model_label}:streamGenerateContent"
            f"?alt=sse&key={self._api_key}"
        )
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}

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
                    yield {"type": "message_start", "metadata": {"model": self.model_label}}
                    yield from self._parse_sse(resp.iter_lines())
            except httpx.HTTPError as exc:
                yield {"type": "error", "error": f"transport error: {exc}", "recoverable": True}
                yield {"type": "message_stop", "stop_reason": "error", "usage": {}}
        finally:
            if close_client:
                client.close()

    def _build_body(
        self,
        *,
        capability: str,
        prompt: str,
        grounding: Dict[str, Any],
        tools: Optional[List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        system_text = f"Capability: {capability}\n\n" + format_grounding_system_prompt(grounding)
        body: Dict[str, Any] = {
            "systemInstruction": {"role": "system", "parts": [{"text": system_text}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        }
        if tools:
            body["tools"] = [
                {
                    "functionDeclarations": [
                        {
                            "name": t["name"],
                            "description": t.get("description", ""),
                            "parameters": t.get("input_schema") or {"type": "object", "properties": {}},
                        }
                        for t in tools
                    ]
                }
            ]
        return body

    def _parse_sse(self, lines: Iterator[str]) -> Iterator[Dict[str, Any]]:
        usage: Dict[str, Any] = {}
        finish_reason: Optional[str] = None
        for raw_line in lines:
            if not raw_line:
                continue
            line = raw_line.strip()
            if not line.startswith("data:"):
                continue
            data_str = line[len("data:"):].strip()
            if not data_str or data_str == "[DONE]":
                continue
            try:
                event = json.loads(data_str)
            except json.JSONDecodeError:
                continue
            for candidate in event.get("candidates", []) or []:
                content = candidate.get("content", {}) or {}
                for part in content.get("parts", []) or []:
                    if "text" in part and part["text"]:
                        yield {"type": "text_delta", "text": part["text"]}
                    elif "functionCall" in part:
                        fc = part["functionCall"]
                        yield {
                            "type": "tool_use",
                            "tool_use_id": fc.get("name", "tool") + "-0",
                            "name": fc.get("name"),
                            "input": fc.get("args") or {},
                        }
                if candidate.get("finishReason"):
                    finish_reason = candidate["finishReason"]
            if event.get("usageMetadata"):
                usage = event["usageMetadata"]

        normalized_stop = {
            "STOP": "end_turn",
            "MAX_TOKENS": "max_tokens",
            "TOOL_USE": "tool_use",
            "SAFETY": "error",
        }.get((finish_reason or "").upper(), "end_turn")

        yield {
            "type": "message_stop",
            "stop_reason": normalized_stop,
            "usage": {
                "input_tokens": usage.get("promptTokenCount", 0),
                "output_tokens": usage.get("candidatesTokenCount", 0),
            },
            "raw": {"provider": "gemini", "finish_reason": finish_reason},
        }
