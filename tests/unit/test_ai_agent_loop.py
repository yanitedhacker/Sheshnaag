"""Unit tests for the ReAct-style AIAgentLoop."""

from __future__ import annotations

from typing import Any, Dict, Iterator, List

from app.services.ai_agent_loop import AIAgentLoop
from app.services.ai_tools_registry import Tool


class _ScriptedAdapter:
    """Adapter that yields a different canned stream on each call."""

    provider_key = "scripted"
    display_name = "Scripted"
    model_label = "scripted-1"
    capabilities = ["summarize_evidence"]

    def __init__(self, scripts: List[List[Dict[str, Any]]]) -> None:
        self._scripts = list(scripts)
        self.calls: List[Dict[str, Any]] = []

    def health(self) -> Dict[str, Any]:
        return {"status": "available", "healthy": True, "model": self.model_label}

    def stream(self, **kwargs: Any) -> Iterator[Dict[str, Any]]:
        self.calls.append(kwargs)
        if not self._scripts:
            yield {"type": "message_stop", "stop_reason": "end_turn", "usage": {}}
            return
        script = self._scripts.pop(0)
        for ev in script:
            yield ev


def test_agent_loop_executes_tool_then_ends_turn():
    # Step 1: model emits one tool_use, stop_reason=tool_use.
    # Step 2: model emits final text, stop_reason=end_turn.
    step1 = [
        {"type": "message_start", "metadata": {"model": "scripted-1"}},
        {"type": "tool_use", "tool_use_id": "tu_1", "name": "echo_tool", "input": {"value": "hello"}},
        {"type": "message_stop", "stop_reason": "tool_use", "usage": {"input_tokens": 10, "output_tokens": 3}},
    ]
    step2 = [
        {"type": "message_start", "metadata": {"model": "scripted-1"}},
        {"type": "text_delta", "text": "Done. The tool returned the value 'hello'."},
        {"type": "message_stop", "stop_reason": "end_turn", "usage": {"input_tokens": 12, "output_tokens": 9}},
    ]
    adapter = _ScriptedAdapter([step1, step2])

    calls = {"count": 0}

    def echo(value: str, **_: Any) -> Dict[str, Any]:
        calls["count"] += 1
        return {"echoed": value}

    tools = {
        "echo_tool": Tool(
            name="echo_tool",
            description="echoes its input",
            input_schema={"type": "object", "properties": {"value": {"type": "string"}}},
            capability=None,
            callable=echo,
        )
    }

    loop = AIAgentLoop(adapter_provider=lambda _: adapter, tools=tools)
    result = loop.run(
        provider_key="scripted",
        initial_prompt="Please use the echo tool.",
        grounding={"items": [{"label": "a", "summary": "b"}]},
        max_steps=5,
        tenant_id=1,
        actor="alice@example.com",
    )

    assert len(result.steps) == 2
    assert result.final_stop_reason == "end_turn"
    assert result.final_text.startswith("Done.")
    assert calls["count"] == 1

    # Step 1 recorded tool execution.
    assert len(result.steps[0].tool_uses) == 1
    assert len(result.steps[0].tool_results) == 1
    assert result.steps[0].tool_results[0]["result"] == {"echoed": "hello"}
    assert result.steps[0].tool_results[0]["error"] is None

    # Token totals aggregate correctly.
    assert result.total_usage["input_tokens"] == 22
    assert result.total_usage["output_tokens"] == 12

    # The second adapter call's prompt summarizes the tool result.
    second_prompt = adapter.calls[1]["prompt"]
    assert "echo_tool" in second_prompt
    assert "'echoed': 'hello'" in second_prompt or "echoed" in second_prompt


def test_agent_loop_caps_steps():
    # Each scripted step keeps emitting tool_use forever.
    forever_step = [
        {"type": "tool_use", "tool_use_id": "tu_x", "name": "echo_tool", "input": {"value": "v"}},
        {"type": "message_stop", "stop_reason": "tool_use", "usage": {"input_tokens": 1, "output_tokens": 1}},
    ]
    adapter = _ScriptedAdapter([list(forever_step) for _ in range(10)])

    tools = {
        "echo_tool": Tool(
            name="echo_tool",
            description="echoes",
            input_schema={"type": "object"},
            capability=None,
            callable=lambda **kw: {"ok": True},
        )
    }
    loop = AIAgentLoop(adapter_provider=lambda _: adapter, tools=tools)
    result = loop.run(
        provider_key="scripted",
        initial_prompt="please loop",
        grounding={"items": [{"label": "g"}]},
        max_steps=3,
    )
    assert len(result.steps) == 3


def test_agent_loop_handles_unknown_tool():
    step = [
        {"type": "tool_use", "tool_use_id": "tu_1", "name": "does_not_exist", "input": {}},
        {"type": "message_stop", "stop_reason": "tool_use", "usage": {}},
    ]
    final = [
        {"type": "text_delta", "text": "bailing out"},
        {"type": "message_stop", "stop_reason": "end_turn", "usage": {}},
    ]
    adapter = _ScriptedAdapter([step, final])
    loop = AIAgentLoop(adapter_provider=lambda _: adapter, tools={})
    result = loop.run(
        provider_key="scripted",
        initial_prompt="do stuff",
        grounding={"items": [{"label": "g"}]},
        max_steps=3,
    )
    assert result.steps[0].tool_results[0]["error"].startswith("unknown tool")


def test_agent_loop_enforces_capability_policy_when_denied():
    # Monkey-patch the capability evaluator via dependency injection.
    step = [
        {"type": "tool_use", "tool_use_id": "tu_1", "name": "danger_tool", "input": {"a": 1}},
        {"type": "message_stop", "stop_reason": "tool_use", "usage": {}},
    ]
    terminal = [
        {"type": "text_delta", "text": "ok"},
        {"type": "message_stop", "stop_reason": "end_turn", "usage": {}},
    ]
    adapter = _ScriptedAdapter([step, terminal])

    denial_called = {"n": 0}

    class FakeDecision:
        def __init__(self) -> None:
            self.permitted = False
            self.reason = "no artifact"

    class FakePolicy:
        def evaluate(self, *, capability, scope, actor):
            denial_called["n"] += 1
            return FakeDecision()

    # Inject a fake capability_policy module into sys.modules.
    import sys
    import types

    fake_mod = types.ModuleType("app.services.capability_policy")
    fake_mod.CapabilityPolicy = FakePolicy  # type: ignore[attr-defined]
    sys.modules["app.services.capability_policy"] = fake_mod
    try:
        tools = {
            "danger_tool": Tool(
                name="danger_tool",
                description="needs capability",
                input_schema={"type": "object"},
                capability="dynamic_detonation",
                callable=lambda **kw: {"ran": True},
            )
        }
        loop = AIAgentLoop(adapter_provider=lambda _: adapter, tools=tools)
        result = loop.run(
            provider_key="scripted",
            initial_prompt="please run the danger tool",
            grounding={"items": [{"label": "g"}]},
            max_steps=4,
            tenant_id=1,
            actor="alice",
        )
        assert denial_called["n"] == 1
        assert "denied" in result.steps[0].tool_results[0]["error"]
        assert result.steps[0].tool_results[0]["result"] is None
    finally:
        sys.modules.pop("app.services.capability_policy", None)
