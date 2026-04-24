"""Unit tests for the native AI provider adapters."""

from __future__ import annotations

import contextlib
import json
from typing import Any, Dict, Iterable, List
from unittest.mock import MagicMock

import httpx
import pytest

from app.services.ai_adapters import (
    AnthropicAdapter,
    AzureOpenAIAdapter,
    BedrockAdapter,
    GeminiAdapter,
    LocalOpenAICompatAdapter,
    OpenAIAdapter,
    collect_stream,
)


# -- Helpers ------------------------------------------------------------------


class _FakeStreamResponse:
    """Mimics the object returned by httpx.Client.stream(...) as a ctx manager."""

    def __init__(self, lines: Iterable[str], status_code: int = 200) -> None:
        self.status_code = status_code
        self._lines = list(lines)
        self._body = "\n".join(self._lines).encode("utf-8")

    def iter_lines(self):
        for ln in self._lines:
            yield ln

    def read(self) -> bytes:
        return self._body


class _FakeClient:
    """Minimal httpx.Client stand-in capturing the last POST + returning canned SSE."""

    def __init__(self, lines: Iterable[str], status_code: int = 200) -> None:
        self._lines = list(lines)
        self._status = status_code
        self.last_request: Dict[str, Any] = {}

    @contextlib.contextmanager
    def stream(self, method: str, url: str, headers=None, json=None):
        self.last_request = {"method": method, "url": url, "headers": headers, "json": json}
        yield _FakeStreamResponse(self._lines, status_code=self._status)

    def get(self, url: str):  # for local health check
        self.last_request = {"method": "GET", "url": url}
        resp = MagicMock()
        resp.status_code = 200
        return resp

    def close(self) -> None:
        pass


def _sse(event: Dict[str, Any]) -> str:
    return f"data: {json.dumps(event)}"


# -- Anthropic ----------------------------------------------------------------


def test_anthropic_adapter_health_missing_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    h = AnthropicAdapter(api_key=None).health()
    assert h["healthy"] is False
    assert "ANTHROPIC_API_KEY" in h["missing_configuration"]


def test_anthropic_adapter_health_configured(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    h = AnthropicAdapter().health()
    assert h["healthy"] is True
    assert h["status"] == "available"


def test_anthropic_adapter_streams_text_and_stops():
    lines = [
        _sse({"type": "message_start", "message": {"id": "msg_1", "model": "claude-3-5-sonnet", "usage": {"input_tokens": 9}}}),
        _sse({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        _sse({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hello"}}),
        _sse({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": " world"}}),
        _sse({"type": "content_block_stop", "index": 0}),
        _sse({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 2}}),
        _sse({"type": "message_stop"}),
    ]
    client = _FakeClient(lines)
    adapter = AnthropicAdapter(api_key="sk-ant-test", http_client=client)
    events = list(adapter.stream(
        capability="summarize_evidence",
        prompt="hi",
        grounding={"items": [{"label": "x", "summary": "y"}]},
        tools=[{"name": "query_knowledge", "description": "rag", "input_schema": {"type": "object"}}],
    ))
    result = collect_stream(events)
    assert "Hello world" in result["text"]
    assert result["stop_reason"] == "end_turn"
    # Ensure cache_control landed on the tool and the system block.
    body = client.last_request["json"]
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert body["tools"][0]["cache_control"] == {"type": "ephemeral"}


def test_anthropic_adapter_parses_tool_use():
    lines = [
        _sse({"type": "message_start", "message": {"id": "m", "usage": {"input_tokens": 1}}}),
        _sse({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "tu_1", "name": "query_knowledge"}}),
        _sse({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{\"query\": "}}),
        _sse({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "\"malware\"}"}}),
        _sse({"type": "content_block_stop", "index": 0}),
        _sse({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 7}}),
        _sse({"type": "message_stop"}),
    ]
    client = _FakeClient(lines)
    adapter = AnthropicAdapter(api_key="x", http_client=client)
    events = list(adapter.stream(
        capability="summarize_evidence",
        prompt="hi",
        grounding={"items": [{"label": "x"}]},
    ))
    agg = collect_stream(events)
    assert agg["stop_reason"] == "tool_use"
    assert len(agg["tool_uses"]) == 1
    assert agg["tool_uses"][0]["name"] == "query_knowledge"
    assert agg["tool_uses"][0]["input"] == {"query": "malware"}


# -- OpenAI -------------------------------------------------------------------


def test_openai_adapter_health_missing_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert OpenAIAdapter(api_key=None).health()["healthy"] is False


def test_openai_adapter_health_configured():
    assert OpenAIAdapter(api_key="sk-test").health()["healthy"] is True


def test_openai_adapter_streams_text_and_stops():
    lines = [
        _sse({"id": "c1", "model": "gpt-4o", "choices": [{"delta": {"content": "Hel"}}]}),
        _sse({"id": "c1", "choices": [{"delta": {"content": "lo"}}]}),
        _sse({"id": "c1", "choices": [{"delta": {}, "finish_reason": "stop"}]}),
        _sse({"usage": {"prompt_tokens": 3, "completion_tokens": 5}, "choices": []}),
        "data: [DONE]",
    ]
    client = _FakeClient(lines)
    adapter = OpenAIAdapter(api_key="sk-test", http_client=client)
    events = list(adapter.stream(
        capability="summarize_evidence",
        prompt="hi",
        grounding={"items": [{"label": "x"}]},
        tools=[{"name": "query_knowledge", "description": "rag", "input_schema": {"type": "object"}}],
    ))
    agg = collect_stream(events)
    assert agg["text"] == "Hello"
    assert agg["stop_reason"] == "end_turn"
    # Function-call tool shape.
    body = client.last_request["json"]
    assert body["tools"][0]["type"] == "function"
    assert body["tools"][0]["function"]["name"] == "query_knowledge"


def test_openai_adapter_emits_tool_use_from_tool_calls():
    lines = [
        _sse({"id": "c", "model": "gpt", "choices": [{"delta": {"tool_calls": [
            {"index": 0, "id": "call_1", "function": {"name": "pivot_ioc", "arguments": "{\"ind"}},
        ]}}]}),
        _sse({"choices": [{"delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": "icator_value\": \"1.2.3.4\"}"}},
        ]}}]}),
        _sse({"choices": [{"delta": {}, "finish_reason": "tool_calls"}]}),
        "data: [DONE]",
    ]
    client = _FakeClient(lines)
    adapter = OpenAIAdapter(api_key="sk-test", http_client=client)
    events = list(adapter.stream(
        capability="summarize_evidence",
        prompt="hi",
        grounding={"items": [{"label": "x"}]},
    ))
    agg = collect_stream(events)
    assert agg["stop_reason"] == "tool_use"
    assert agg["tool_uses"][0]["name"] == "pivot_ioc"
    assert agg["tool_uses"][0]["input"] == {"indicator_value": "1.2.3.4"}


# -- Gemini -------------------------------------------------------------------


def test_gemini_adapter_health_missing_key(monkeypatch):
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert GeminiAdapter(api_key=None).health()["healthy"] is False


def test_gemini_adapter_health_configured():
    assert GeminiAdapter(api_key="g-test").health()["healthy"] is True


def test_gemini_adapter_streams_text_and_stops():
    lines = [
        _sse({"candidates": [{"content": {"parts": [{"text": "Hi"}]}}]}),
        _sse({"candidates": [{"content": {"parts": [{"text": " there"}]}, "finishReason": "STOP"}],
              "usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 2}}),
    ]
    client = _FakeClient(lines)
    adapter = GeminiAdapter(api_key="g-test", http_client=client)
    events = list(adapter.stream(
        capability="summarize_evidence",
        prompt="hi",
        grounding={"items": [{"label": "x"}]},
        tools=[{"name": "query_knowledge", "description": "rag", "input_schema": {"type": "object"}}],
    ))
    agg = collect_stream(events)
    assert agg["text"] == "Hi there"
    assert agg["stop_reason"] == "end_turn"
    # Confirm function declaration shape.
    body = client.last_request["json"]
    assert body["tools"][0]["functionDeclarations"][0]["name"] == "query_knowledge"
    assert "key=g-test" in client.last_request["url"]


# -- Azure OpenAI -------------------------------------------------------------


def test_azure_adapter_health_missing_config(monkeypatch):
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    h = AzureOpenAIAdapter().health()
    assert h["healthy"] is False
    assert "AZURE_OPENAI_API_KEY" in h["missing_configuration"]
    assert "AZURE_OPENAI_ENDPOINT" in h["missing_configuration"]


def test_azure_adapter_health_configured(monkeypatch):
    adapter = AzureOpenAIAdapter(
        api_key="az-key",
        endpoint="https://x.openai.azure.com",
        deployment="gpt-4o",
        api_version="2024-08-01-preview",
    )
    h = adapter.health()
    assert h["healthy"] is True
    assert h["endpoint"] == "https://x.openai.azure.com"


def test_azure_adapter_streams_against_deployment_url():
    lines = [
        _sse({"id": "c1", "model": "gpt-4o", "choices": [{"delta": {"content": "yo"}}]}),
        _sse({"choices": [{"delta": {}, "finish_reason": "stop"}]}),
        "data: [DONE]",
    ]
    client = _FakeClient(lines)
    adapter = AzureOpenAIAdapter(
        api_key="az-key",
        endpoint="https://x.openai.azure.com",
        deployment="gpt-4o",
        api_version="2024-08-01-preview",
        http_client=client,
    )
    events = list(adapter.stream(
        capability="summarize_evidence",
        prompt="hi",
        grounding={"items": [{"label": "x"}]},
    ))
    agg = collect_stream(events)
    assert agg["text"] == "yo"
    url = client.last_request["url"]
    assert "/openai/deployments/gpt-4o/chat/completions" in url
    assert "api-version=2024-08-01-preview" in url
    assert client.last_request["headers"]["api-key"] == "az-key"


# -- Bedrock ------------------------------------------------------------------


def test_bedrock_adapter_health_missing_credentials(monkeypatch):
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(key, raising=False)
    adapter = BedrockAdapter()
    h = adapter.health()
    assert h["healthy"] is False


def test_bedrock_adapter_health_configured(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    # Inject a fake client so boto3 need not be installed.
    adapter = BedrockAdapter(bedrock_client=MagicMock())
    h = adapter.health()
    assert h["healthy"] is True


def test_bedrock_adapter_streams_anthropic_family():
    # Two content deltas + message_delta with end_turn.
    chunks = [
        {"chunk": {"bytes": json.dumps({
            "type": "content_block_delta",
            "delta": {"type": "text_delta", "text": "hello"},
        }).encode("utf-8")}},
        {"chunk": {"bytes": json.dumps({
            "type": "content_block_delta",
            "delta": {"type": "text_delta", "text": " bedrock"},
        }).encode("utf-8")}},
        {"chunk": {"bytes": json.dumps({
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn"},
            "usage": {"input_tokens": 5, "output_tokens": 2},
        }).encode("utf-8")}},
    ]
    fake_client = MagicMock()
    fake_client.invoke_model_with_response_stream.return_value = {"body": iter(chunks)}

    adapter = BedrockAdapter(
        region="us-east-1",
        model_id="anthropic.claude-3-5-sonnet-20241022-v2:0",
        bedrock_client=fake_client,
    )
    events = list(adapter.stream(
        capability="summarize_evidence",
        prompt="hi",
        grounding={"items": [{"label": "x"}]},
    ))
    agg = collect_stream(events)
    assert agg["text"] == "hello bedrock"
    assert agg["stop_reason"] == "end_turn"
    # Confirm body was serialized per-family.
    kwargs = fake_client.invoke_model_with_response_stream.call_args.kwargs
    body = json.loads(kwargs["body"])
    assert body["anthropic_version"] == "bedrock-2023-05-31"
    assert body["messages"][0]["role"] == "user"


def test_bedrock_adapter_streams_titan_family():
    chunks = [
        {"chunk": {"bytes": json.dumps({
            "outputText": "titan says hi",
            "completionReason": "FINISH",
            "inputTextTokenCount": 3,
            "totalOutputTextTokenCount": 4,
        }).encode("utf-8")}},
    ]
    fake_client = MagicMock()
    fake_client.invoke_model_with_response_stream.return_value = {"body": iter(chunks)}
    adapter = BedrockAdapter(
        region="us-west-2",
        model_id="amazon.titan-text-lite-v1",
        bedrock_client=fake_client,
    )
    events = list(adapter.stream(
        capability="summarize_evidence",
        prompt="hi",
        grounding={"items": [{"label": "x"}]},
    ))
    agg = collect_stream(events)
    assert "titan says hi" in agg["text"]


# -- Local --------------------------------------------------------------------


def test_local_adapter_health_probes_base_url():
    client = _FakeClient(lines=[])
    adapter = LocalOpenAICompatAdapter(base_url="http://localhost:11434/v1", http_client=client)
    h = adapter.health()
    assert h["healthy"] is True
    assert h["base_url"].endswith("/v1")


def test_local_adapter_streams_openai_compatible():
    lines = [
        _sse({"id": "c", "model": "llama3.1:8b", "choices": [{"delta": {"content": "local hi"}}]}),
        _sse({"choices": [{"delta": {}, "finish_reason": "stop"}]}),
        "data: [DONE]",
    ]
    client = _FakeClient(lines)
    adapter = LocalOpenAICompatAdapter(
        base_url="http://localhost:11434/v1",
        model="llama3.1:8b",
        http_client=client,
    )
    events = list(adapter.stream(
        capability="summarize_evidence",
        prompt="hi",
        grounding={"items": [{"label": "x"}]},
    ))
    agg = collect_stream(events)
    assert agg["text"] == "local hi"
    assert agg["stop_reason"] == "end_turn"


# -- Error surface ------------------------------------------------------------


def test_openai_adapter_surfaces_http_error_as_event():
    client = _FakeClient(lines=[], status_code=503)
    adapter = OpenAIAdapter(api_key="sk-test", http_client=client)
    events = list(adapter.stream(
        capability="summarize_evidence",
        prompt="hi",
        grounding={"items": [{"label": "x"}]},
    ))
    agg = collect_stream(events)
    assert agg["stop_reason"] == "error"
    assert agg["errors"]
