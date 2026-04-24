"""AWS Bedrock adapter with per-model request body shapes + SigV4 via boto3."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterator, List, Optional

from app.services.ai_adapters.base import format_grounding_system_prompt


DEFAULT_MODEL = "anthropic.claude-3-5-sonnet-20241022-v2:0"
DEFAULT_REGION = "us-east-1"


class BedrockAdapter:
    """InvokeModelWithResponseStream via boto3.

    Handles the five model families that ship on Bedrock: Claude (Anthropic),
    Titan (Amazon), Cohere, Mistral, and Llama. Each has its own request body
    shape and its own streaming chunk format.
    """

    provider_key = "bedrock"
    display_name = "AWS Bedrock"

    def __init__(
        self,
        *,
        region: Optional[str] = None,
        model_id: Optional[str] = None,
        bedrock_client: Optional[Any] = None,
    ) -> None:
        self._region = region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or DEFAULT_REGION
        self.model_label = model_id or os.getenv("BEDROCK_MODEL_ID") or DEFAULT_MODEL
        self._client = bedrock_client  # Injected for tests.
        self.capabilities = [
            "summarize_evidence",
            "cluster_iocs",
            "draft_hypotheses",
            "generate_detection_candidates",
            "draft_mitigation",
            "draft_report_sections",
            "variant_diff_review",
        ]

    # -- config ---------------------------------------------------------------

    def _has_credentials(self) -> bool:
        # boto3 walks: env -> shared credentials -> IAM role. Any of those is fine.
        if os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"):
            return True
        if os.getenv("AWS_PROFILE"):
            return True
        # Container / instance role — we can't fully detect without boto3 imports,
        # so we optimistically return True when AWS_REGION is set and no explicit
        # keys are present. Failure will surface as an API error during stream.
        return bool(os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION"))

    def health(self) -> Dict[str, Any]:
        missing: List[str] = []
        has_creds = self._has_credentials() or self._client is not None
        if not has_creds:
            missing.append("AWS credentials (AWS_ACCESS_KEY_ID / AWS_PROFILE / IAM role)")
        try:
            import boto3  # noqa: F401
            boto3_available = True
        except ImportError:
            boto3_available = False
            if self._client is None:
                missing.append("boto3")
        return {
            "status": "available" if not missing else "unconfigured",
            "healthy": not missing,
            "model": self.model_label,
            "region": self._region,
            "boto3_available": boto3_available,
            "missing_configuration": missing,
        }

    # -- streaming -----------------------------------------------------------

    def stream(
        self,
        *,
        capability: str,
        prompt: str,
        grounding: Dict[str, Any],
        tools: Optional[List[Dict[str, Any]]] = None,
        cache_key: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        client = self._client
        if client is None:
            try:
                import boto3
            except ImportError:
                yield {"type": "error", "error": "boto3 not installed", "recoverable": False}
                yield {"type": "message_stop", "stop_reason": "error", "usage": {}}
                return
            try:
                client = boto3.client("bedrock-runtime", region_name=self._region)
            except Exception as exc:  # pragma: no cover - exercised via integration
                yield {"type": "error", "error": f"bedrock client init: {exc}", "recoverable": False}
                yield {"type": "message_stop", "stop_reason": "error", "usage": {}}
                return

        body = self._build_body(capability=capability, prompt=prompt, grounding=grounding, tools=tools)

        yield {"type": "message_start", "metadata": {"model": self.model_label, "region": self._region}}
        try:
            resp = client.invoke_model_with_response_stream(
                modelId=self.model_label,
                body=json.dumps(body).encode("utf-8"),
                contentType="application/json",
                accept="application/json",
            )
        except Exception as exc:
            yield {"type": "error", "error": f"bedrock invoke error: {exc}", "recoverable": True}
            yield {"type": "message_stop", "stop_reason": "error", "usage": {}}
            return

        family = self._model_family()
        stream = resp.get("body") if isinstance(resp, dict) else getattr(resp, "body", None)
        if stream is None:
            yield {"type": "error", "error": "bedrock response missing body stream", "recoverable": False}
            yield {"type": "message_stop", "stop_reason": "error", "usage": {}}
            return

        usage = {"input_tokens": 0, "output_tokens": 0}
        stop_reason = "end_turn"

        for event in stream:
            chunk = event.get("chunk") if isinstance(event, dict) else None
            if not chunk:
                continue
            raw_bytes = chunk.get("bytes")
            if isinstance(raw_bytes, (bytes, bytearray)):
                try:
                    payload = json.loads(raw_bytes.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
            elif isinstance(raw_bytes, str):
                try:
                    payload = json.loads(raw_bytes)
                except json.JSONDecodeError:
                    continue
            else:
                continue

            for ev in self._decode_chunk(family, payload, usage_sink=usage):
                if ev.get("type") == "message_stop":
                    stop_reason = ev.get("stop_reason", stop_reason)
                    continue
                if ev.get("_stop_reason"):
                    stop_reason = ev.pop("_stop_reason")
                yield ev

        yield {
            "type": "message_stop",
            "stop_reason": stop_reason,
            "usage": usage,
            "raw": {"provider": "bedrock", "family": family},
        }

    # -- body construction per model family ---------------------------------

    def _model_family(self) -> str:
        mid = self.model_label.lower()
        if mid.startswith("anthropic.") or "claude" in mid:
            return "anthropic"
        if mid.startswith("amazon.titan") or "titan" in mid:
            return "titan"
        if mid.startswith("cohere."):
            return "cohere"
        if mid.startswith("mistral.") or mid.startswith("meta.") is False and "mistral" in mid:
            return "mistral"
        if mid.startswith("meta.") or "llama" in mid:
            return "llama"
        return "anthropic"  # sensible default

    def _build_body(
        self,
        *,
        capability: str,
        prompt: str,
        grounding: Dict[str, Any],
        tools: Optional[List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        family = self._model_family()
        system_text = f"Capability: {capability}\n\n" + format_grounding_system_prompt(grounding)

        if family == "anthropic":
            body: Dict[str, Any] = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 4096,
                "system": system_text,
                "messages": [{"role": "user", "content": prompt}],
            }
            if tools:
                body["tools"] = [
                    {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "input_schema": t.get("input_schema") or {"type": "object", "properties": {}},
                    }
                    for t in tools
                ]
            return body

        if family == "titan":
            return {
                "inputText": f"{system_text}\n\nUser: {prompt}\n\nAssistant:",
                "textGenerationConfig": {"maxTokenCount": 2048, "temperature": 0.2},
            }

        if family == "cohere":
            return {
                "message": prompt,
                "preamble": system_text,
                "max_tokens": 2048,
                "stream": True,
            }

        if family == "mistral":
            return {
                "prompt": f"<s>[INST] {system_text}\n\n{prompt} [/INST]",
                "max_tokens": 2048,
                "temperature": 0.2,
            }

        if family == "llama":
            return {
                "prompt": (
                    "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
                    f"{system_text}<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n"
                    f"{prompt}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"
                ),
                "max_gen_len": 2048,
                "temperature": 0.2,
            }

        return {"inputText": prompt}

    # -- streaming chunk decoding per family --------------------------------

    def _decode_chunk(
        self,
        family: str,
        payload: Dict[str, Any],
        *,
        usage_sink: Dict[str, int],
    ) -> Iterator[Dict[str, Any]]:
        if family == "anthropic":
            etype = payload.get("type")
            if etype == "content_block_delta":
                d = payload.get("delta", {}) or {}
                if d.get("type") == "text_delta" and d.get("text"):
                    yield {"type": "text_delta", "text": d["text"]}
            elif etype == "message_delta":
                stop = (payload.get("delta") or {}).get("stop_reason")
                u = payload.get("usage") or {}
                if u:
                    usage_sink["input_tokens"] = usage_sink.get("input_tokens", 0) + int(u.get("input_tokens", 0))
                    usage_sink["output_tokens"] = usage_sink.get("output_tokens", 0) + int(u.get("output_tokens", 0))
                if stop:
                    normalized = {"tool_use": "tool_use", "max_tokens": "max_tokens"}.get(stop, "end_turn")
                    yield {"type": "noop", "_stop_reason": normalized}
            elif etype == "content_block_start":
                block = payload.get("content_block", {}) or {}
                if block.get("type") == "tool_use":
                    yield {
                        "type": "tool_use",
                        "tool_use_id": block.get("id"),
                        "name": block.get("name"),
                        "input": block.get("input") or {},
                    }
            return

        if family == "titan":
            text = payload.get("outputText")
            if text:
                yield {"type": "text_delta", "text": text}
            if payload.get("completionReason"):
                usage_sink["input_tokens"] = payload.get("inputTextTokenCount", 0)
                usage_sink["output_tokens"] = payload.get("totalOutputTextTokenCount", 0)
            return

        if family == "cohere":
            # Cohere streams {"is_finished":false,"event_type":"text-generation","text":"..."}
            if payload.get("event_type") == "text-generation" and payload.get("text"):
                yield {"type": "text_delta", "text": payload["text"]}
            if payload.get("is_finished"):
                usage_sink["output_tokens"] = int(
                    payload.get("response", {}).get("meta", {}).get("billed_units", {}).get("output_tokens", 0)
                )
            return

        if family == "mistral":
            for out in payload.get("outputs", []) or []:
                if out.get("text"):
                    yield {"type": "text_delta", "text": out["text"]}
            return

        if family == "llama":
            if payload.get("generation"):
                yield {"type": "text_delta", "text": payload["generation"]}
            if payload.get("stop_reason"):
                usage_sink["input_tokens"] = payload.get("prompt_token_count", 0)
                usage_sink["output_tokens"] = payload.get("generation_token_count", 0)
            return

        # Unknown family — try generic text
        if isinstance(payload.get("completion"), str):
            yield {"type": "text_delta", "text": payload["completion"]}
