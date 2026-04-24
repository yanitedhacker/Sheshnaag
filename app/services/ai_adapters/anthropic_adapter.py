"""Native Anthropic Messages API adapter with SSE streaming + tool use."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterator, List, Optional

import httpx

from app.services.ai_adapters.base import format_grounding_system_prompt


DEFAULT_MODEL = "claude-3-5-sonnet-latest"
DEFAULT_BASE_URL = "https://api.anthropic.com"
ANTHROPIC_API_VERSION = "2023-06-01"
DEFAULT_MAX_TOKENS = 4096


class AnthropicAdapter:
    """POSTs to /v1/messages. SSE streaming. Tool use + prompt caching."""

    provider_key = "anthropic"
    display_name = "Anthropic Messages API"

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        http_client: Optional[httpx.Client] = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self._api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self._base_url = (base_url or os.getenv("ANTHROPIC_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.model_label = model or os.getenv("ANTHROPIC_MODEL") or DEFAULT_MODEL
        self._http = http_client
        self._max_tokens = max_tokens
        self.capabilities = [
            "summarize_evidence",
            "cluster_iocs",
            "draft_hypotheses",
            "generate_detection_candidates",
            "draft_mitigation",
            "draft_report_sections",
            "variant_diff_review",
        ]

    # -- public API -----------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        missing: List[str] = []
        if not self._api_key:
            missing.append("ANTHROPIC_API_KEY")
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
            yield {"type": "error", "error": "ANTHROPIC_API_KEY not set", "recoverable": False}
            yield {"type": "message_stop", "stop_reason": "error", "usage": {}}
            return

        body = self._build_body(
            capability=capability,
            prompt=prompt,
            grounding=grounding,
            tools=tools,
            cache_key=cache_key,
        )
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_API_VERSION,
            "content-type": "application/json",
            "accept": "text/event-stream",
        }
        url = f"{self._base_url}/v1/messages"

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

    # -- body construction ---------------------------------------------------

    def _build_body(
        self,
        *,
        capability: str,
        prompt: str,
        grounding: Dict[str, Any],
        tools: Optional[List[Dict[str, Any]]],
        cache_key: Optional[str],
    ) -> Dict[str, Any]:
        system_text = (
            f"Capability: {capability}\n\n"
            + format_grounding_system_prompt(grounding)
        )
        # cache_control on the system block (ephemeral) for repeated grounding.
        system_blocks: List[Dict[str, Any]] = [
            {
                "type": "text",
                "text": system_text,
                "cache_control": {"type": "ephemeral"},
            }
        ]

        body: Dict[str, Any] = {
            "model": self.model_label,
            "max_tokens": self._max_tokens,
            "stream": True,
            "system": system_blocks,
            "messages": [{"role": "user", "content": prompt}],
        }
        if tools:
            body["tools"] = [self._encode_tool(t) for t in tools]
        if cache_key:
            # Anthropic does not accept a free-form cache_key but we echo it in
            # metadata so callers can correlate with their own cache bookkeeping.
            body["metadata"] = {"user_id": str(cache_key)[:128]}
        return body

    @staticmethod
    def _encode_tool(tool: Dict[str, Any]) -> Dict[str, Any]:
        encoded = {
            "name": tool["name"],
            "description": tool.get("description", ""),
            "input_schema": tool.get("input_schema") or {"type": "object", "properties": {}},
        }
        # Ephemeral caching on tool definitions — dramatic reuse savings for
        # long-lived tool rosters.
        encoded["cache_control"] = {"type": "ephemeral"}
        return encoded

    # -- SSE parsing ---------------------------------------------------------

    def _parse_sse(self, lines: Iterator[str]) -> Iterator[Dict[str, Any]]:
        current_tool: Optional[Dict[str, Any]] = None
        current_tool_json_parts: List[str] = []
        usage: Dict[str, Any] = {}
        stop_reason = "end_turn"
        started = False

        for raw_line in lines:
            if not raw_line:
                continue
            line = raw_line.strip()
            if not line or line.startswith(":"):
                continue
            if not line.startswith("data:"):
                continue
            data_str = line[len("data:"):].strip()
            if not data_str or data_str == "[DONE]":
                continue
            try:
                event = json.loads(data_str)
            except json.JSONDecodeError:
                continue

            etype = event.get("type")
            if etype == "message_start":
                started = True
                msg = event.get("message", {})
                usage = msg.get("usage", {}) or {}
                yield {"type": "message_start", "metadata": {"id": msg.get("id"), "model": msg.get("model")}}
            elif etype == "content_block_start":
                block = event.get("content_block", {})
                if block.get("type") == "tool_use":
                    current_tool = {
                        "tool_use_id": block.get("id"),
                        "name": block.get("name"),
                    }
                    current_tool_json_parts = []
            elif etype == "content_block_delta":
                delta = event.get("delta", {})
                dtype = delta.get("type")
                if dtype == "text_delta":
                    txt = delta.get("text", "")
                    if txt:
                        yield {"type": "text_delta", "text": txt}
                elif dtype == "input_json_delta":
                    current_tool_json_parts.append(delta.get("partial_json", ""))
            elif etype == "content_block_stop":
                if current_tool is not None:
                    raw = "".join(current_tool_json_parts)
                    try:
                        parsed_input = json.loads(raw) if raw else {}
                    except json.JSONDecodeError:
                        parsed_input = {"_raw": raw}
                    yield {
                        "type": "tool_use",
                        "tool_use_id": current_tool["tool_use_id"],
                        "name": current_tool["name"],
                        "input": parsed_input,
                    }
                    current_tool = None
                    current_tool_json_parts = []
            elif etype == "message_delta":
                delta = event.get("delta", {})
                if delta.get("stop_reason"):
                    stop_reason = delta["stop_reason"]
                if event.get("usage"):
                    usage = {**usage, **event["usage"]}
            elif etype == "message_stop":
                break
            elif etype == "error":
                err = event.get("error", {})
                yield {"type": "error", "error": err.get("message", "anthropic error"), "recoverable": False}
                stop_reason = "error"
                break

        if not started:
            yield {"type": "message_start", "metadata": {"model": self.model_label}}
        # Normalize anthropic stop_reason -> canonical event vocabulary.
        normalized_stop = {
            "end_turn": "end_turn",
            "tool_use": "tool_use",
            "max_tokens": "max_tokens",
            "stop_sequence": "end_turn",
        }.get(stop_reason, stop_reason)
        yield {
            "type": "message_stop",
            "stop_reason": normalized_stop,
            "usage": {
                "input_tokens": usage.get("input_tokens", 0),
                "output_tokens": usage.get("output_tokens", 0),
            },
            "raw": {"provider": "anthropic"},
        }
