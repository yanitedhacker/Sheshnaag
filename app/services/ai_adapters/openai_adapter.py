"""Native OpenAI /v1/chat/completions adapter with SSE streaming + tools."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterator, List, Optional

import httpx

from app.services.ai_adapters.base import format_grounding_system_prompt


DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_BASE_URL = "https://api.openai.com/v1"


class OpenAIAdapter:
    """POSTs to /v1/chat/completions with stream=True. Tool/function calling."""

    provider_key = "openai"
    display_name = "OpenAI Chat Completions"

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        http_client: Optional[httpx.Client] = None,
        organization: Optional[str] = None,
    ) -> None:
        self._api_key = api_key or os.getenv("OPENAI_API_KEY")
        self._base_url = (base_url or os.getenv("OPENAI_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.model_label = model or os.getenv("OPENAI_MODEL") or DEFAULT_MODEL
        self._http = http_client
        self._org = organization or os.getenv("OPENAI_ORG")
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
            missing.append("OPENAI_API_KEY")
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
            yield {"type": "error", "error": "OPENAI_API_KEY not set", "recoverable": False}
            yield {"type": "message_stop", "stop_reason": "error", "usage": {}}
            return

        body = self._build_body(capability=capability, prompt=prompt, grounding=grounding, tools=tools)
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        }
        if self._org:
            headers["OpenAI-Organization"] = self._org
        if cache_key:
            # Newer OpenAI APIs pass a `user` for abuse tracking + implicit caching.
            body["user"] = str(cache_key)[:128]

        url = f"{self._base_url}/chat/completions"
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

    # -- body ---------------------------------------------------------------

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
            "model": self.model_label,
            "stream": True,
            "stream_options": {"include_usage": True},
            "messages": [
                {"role": "system", "content": system_text},
                {"role": "user", "content": prompt},
            ],
        }
        if tools:
            body["tools"] = [self._encode_tool(t) for t in tools]
            body["tool_choice"] = "auto"
        return body

    @staticmethod
    def _encode_tool(tool: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "parameters": tool.get("input_schema") or {"type": "object", "properties": {}},
            },
        }

    # -- SSE parsing --------------------------------------------------------

    def _parse_sse(self, lines: Iterator[str]) -> Iterator[Dict[str, Any]]:
        # Stream of chat completion chunks. tool_calls arrive in deltas keyed by
        # an integer index; accumulate per-index and emit one tool_use at finish.
        started = False
        usage: Dict[str, Any] = {}
        finish_reason: Optional[str] = None
        tool_buffers: Dict[int, Dict[str, Any]] = {}

        for raw_line in lines:
            if not raw_line:
                continue
            line = raw_line.strip()
            if not line or not line.startswith("data:"):
                continue
            data_str = line[len("data:"):].strip()
            if not data_str or data_str == "[DONE]":
                break
            try:
                event = json.loads(data_str)
            except json.JSONDecodeError:
                continue

            if not started:
                started = True
                yield {
                    "type": "message_start",
                    "metadata": {"id": event.get("id"), "model": event.get("model")},
                }

            if event.get("usage"):
                usage = event["usage"]

            for choice in event.get("choices", []) or []:
                delta = choice.get("delta", {}) or {}
                content = delta.get("content")
                if content:
                    yield {"type": "text_delta", "text": content}
                for tc in delta.get("tool_calls", []) or []:
                    idx = tc.get("index", 0)
                    buf = tool_buffers.setdefault(idx, {"name": "", "arguments": "", "id": None})
                    if tc.get("id"):
                        buf["id"] = tc["id"]
                    fn = tc.get("function") or {}
                    if fn.get("name"):
                        buf["name"] = fn["name"]
                    if fn.get("arguments"):
                        buf["arguments"] += fn["arguments"]
                if choice.get("finish_reason"):
                    finish_reason = choice["finish_reason"]

        # Emit buffered tool uses on finish.
        if tool_buffers:
            for idx in sorted(tool_buffers.keys()):
                buf = tool_buffers[idx]
                try:
                    parsed = json.loads(buf["arguments"]) if buf["arguments"] else {}
                except json.JSONDecodeError:
                    parsed = {"_raw": buf["arguments"]}
                yield {
                    "type": "tool_use",
                    "tool_use_id": buf.get("id") or f"tool-{idx}",
                    "name": buf.get("name"),
                    "input": parsed,
                }

        normalized_stop = {
            "stop": "end_turn",
            "length": "max_tokens",
            "tool_calls": "tool_use",
            "function_call": "tool_use",
        }.get(finish_reason or "", "end_turn")

        if not started:
            yield {"type": "message_start", "metadata": {"model": self.model_label}}
        yield {
            "type": "message_stop",
            "stop_reason": normalized_stop,
            "usage": {
                "input_tokens": usage.get("prompt_tokens", 0),
                "output_tokens": usage.get("completion_tokens", 0),
            },
            "raw": {"provider": "openai", "finish_reason": finish_reason},
        }
