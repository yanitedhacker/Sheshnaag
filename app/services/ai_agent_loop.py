"""Bounded ReAct-style agent loop.

Drives a `NativeAIAdapter` through multiple turns, routing `tool_use` events
through the capability policy before executing the tool. Each step is recorded
in the returned `AgentRunResult`; persistence (writing `ai_agent_steps` rows)
is deferred to a later V4 phase that owns the data model.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.services.ai_adapters.base import NativeAIAdapter, collect_stream
from app.services.ai_tools_registry import TOOL_REGISTRY, Tool, get_tool, tool_schemas


logger = logging.getLogger(__name__)


# -- API contract for capability_policy (owned by another agent) --------------

def _eval_capability(capability: str, scope: Dict[str, Any], actor: str) -> None:
    """Evaluate a capability against the policy module.

    Imports are lazy so Phase A slice 1 can land before the policy module does.
    When the policy module is missing OR cannot be constructed in the current
    context (e.g. no DB session bound), we permit-in-dev with a WARNING log.
    Once the policy is wired into the request-scoped DI, every call becomes a
    hard gate.
    """
    try:
        from app.services.capability_policy import CapabilityPolicy  # type: ignore
    except ImportError:
        logger.warning(
            "capability_policy not available; permitting '%s' for dev (actor=%s)",
            capability,
            actor,
        )
        return

    try:
        policy = CapabilityPolicy()
    except TypeError:
        # Module present but requires args we don't have here (e.g. a DB session).
        # Another phase will wire it via DI; default-permit for dev.
        logger.warning(
            "capability_policy requires context we lack in this scope; permitting '%s' for dev",
            capability,
        )
        return

    decision = policy.evaluate(capability=capability, scope=scope, actor=actor)
    if not getattr(decision, "permitted", False):
        raise PermissionError(
            f"capability '{capability}' denied: {getattr(decision, 'reason', 'no reason')}"
        )


# -- Types --------------------------------------------------------------------


@dataclass
class AgentStep:
    step_no: int
    started_at: float
    ended_at: float
    text: str
    tool_uses: List[Dict[str, Any]]
    tool_results: List[Dict[str, Any]]
    stop_reason: str
    usage: Dict[str, Any]
    errors: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "step_no": self.step_no,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": int((self.ended_at - self.started_at) * 1000),
            "text": self.text,
            "tool_uses": self.tool_uses,
            "tool_results": self.tool_results,
            "stop_reason": self.stop_reason,
            "usage": self.usage,
            "errors": self.errors,
        }


@dataclass
class AgentRunResult:
    provider_key: str
    actor: str
    tenant_id: Optional[Any]
    steps: List[AgentStep]
    final_text: str
    final_stop_reason: str
    total_usage: Dict[str, int]
    transcript: List[Dict[str, Any]]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "provider_key": self.provider_key,
            "actor": self.actor,
            "tenant_id": self.tenant_id,
            "steps": [s.as_dict() for s in self.steps],
            "final_text": self.final_text,
            "final_stop_reason": self.final_stop_reason,
            "total_usage": self.total_usage,
            "transcript_length": len(self.transcript),
        }


# -- The loop -----------------------------------------------------------------


class AIAgentLoop:
    """Bounded ReAct loop. One instance per run."""

    def __init__(
        self,
        *,
        adapter_provider: Optional[Any] = None,
        tools: Optional[Dict[str, Tool]] = None,
    ) -> None:
        # `adapter_provider` is a callable `(provider_key) -> NativeAIAdapter`.
        # Default uses the harness. Injectable for tests.
        if adapter_provider is None:
            from app.services.ai_provider_harness import AIProviderHarness

            self._adapter_provider = AIProviderHarness().get_adapter
        else:
            self._adapter_provider = adapter_provider
        self._tools: Dict[str, Tool] = tools if tools is not None else dict(TOOL_REGISTRY)

    def run(
        self,
        *,
        provider_key: str,
        initial_prompt: str,
        grounding: Dict[str, Any],
        max_steps: int = 8,
        tenant_id: Optional[Any] = None,
        actor: str = "system",
        capability: str = "summarize_evidence",
    ) -> AgentRunResult:
        adapter: NativeAIAdapter = self._adapter_provider(provider_key)
        schemas = tool_schemas() if self._tools else []

        transcript: List[Dict[str, Any]] = [
            {"role": "user", "content": initial_prompt}
        ]
        steps: List[AgentStep] = []
        total_usage = {"input_tokens": 0, "output_tokens": 0}

        current_prompt = initial_prompt
        last_text = ""
        last_stop = "end_turn"

        for step_no in range(1, max_steps + 1):
            started = time.monotonic()
            raw_events = adapter.stream(
                capability=capability,
                prompt=current_prompt,
                grounding=grounding,
                tools=schemas,
                cache_key=f"{tenant_id}:{actor}:{provider_key}",
            )
            aggregated = collect_stream(raw_events)
            ended = time.monotonic()

            tool_results: List[Dict[str, Any]] = []
            for tu in aggregated["tool_uses"]:
                tool_results.append(self._execute_tool(tu, tenant_id=tenant_id, actor=actor))

            step = AgentStep(
                step_no=step_no,
                started_at=started,
                ended_at=ended,
                text=aggregated["text"],
                tool_uses=aggregated["tool_uses"],
                tool_results=tool_results,
                stop_reason=aggregated["stop_reason"],
                usage=aggregated["usage"],
                errors=aggregated["errors"],
            )
            steps.append(step)

            total_usage["input_tokens"] += int(aggregated["usage"].get("input_tokens", 0) or 0)
            total_usage["output_tokens"] += int(aggregated["usage"].get("output_tokens", 0) or 0)

            last_text = aggregated["text"] or last_text
            last_stop = aggregated["stop_reason"]

            transcript.append({
                "role": "assistant",
                "content": aggregated["text"],
                "tool_uses": aggregated["tool_uses"],
                "stop_reason": aggregated["stop_reason"],
            })
            if tool_results:
                transcript.append({"role": "tool", "results": tool_results})

            if aggregated["stop_reason"] != "tool_use":
                # Terminal: end_turn, max_tokens, or error.
                break

            if not aggregated["tool_uses"]:
                # Adapter claimed tool_use but emitted no tool — avoid infinite loop.
                logger.warning("adapter %s reported tool_use with no tool payload; halting", provider_key)
                break

            # Next turn's prompt: a compact tool-results summary.
            current_prompt = self._format_tool_results_prompt(tool_results)

        return AgentRunResult(
            provider_key=provider_key,
            actor=actor,
            tenant_id=tenant_id,
            steps=steps,
            final_text=last_text,
            final_stop_reason=last_stop,
            total_usage=total_usage,
            transcript=transcript,
        )

    # -- internals ------------------------------------------------------------

    def _execute_tool(
        self,
        tool_use: Dict[str, Any],
        *,
        tenant_id: Optional[Any],
        actor: str,
    ) -> Dict[str, Any]:
        name = tool_use.get("name")
        args = tool_use.get("input") or {}
        tu_id = tool_use.get("tool_use_id")

        tool = self._tools.get(name) if name else None
        if tool is None:
            return {
                "tool_use_id": tu_id,
                "name": name,
                "error": f"unknown tool '{name}'",
                "result": None,
            }

        if tool.capability:
            try:
                _eval_capability(
                    tool.capability,
                    {"tenant_id": tenant_id, "tool": name, "args": args},
                    actor,
                )
            except PermissionError as exc:
                return {
                    "tool_use_id": tu_id,
                    "name": name,
                    "error": str(exc),
                    "result": None,
                    "capability": tool.capability,
                }

        try:
            kwargs = dict(args) if isinstance(args, dict) else {}
            if getattr(tool, "requires_context", False):
                # Phase B: real tool implementations need DB context. Spin up a
                # short-lived sync session for the tool call and tear it down
                # so the loop doesn't hold a long-running DB connection across
                # an LLM round-trip.
                from app.core.database import SessionLocal

                with SessionLocal() as session:
                    kwargs["_context"] = {
                        "session": session,
                        "tenant_id": tenant_id,
                        "actor": actor,
                    }
                    result = tool.callable(**kwargs)
            else:
                result = tool.callable(**kwargs) if isinstance(args, dict) else tool.callable(args)
        except TypeError as exc:
            return {
                "tool_use_id": tu_id,
                "name": name,
                "error": f"bad arguments: {exc}",
                "result": None,
            }
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("tool %s raised", name)
            return {
                "tool_use_id": tu_id,
                "name": name,
                "error": f"{type(exc).__name__}: {exc}",
                "result": None,
            }

        return {
            "tool_use_id": tu_id,
            "name": name,
            "error": None,
            "result": result,
            "capability": tool.capability,
        }

    @staticmethod
    def _format_tool_results_prompt(tool_results: List[Dict[str, Any]]) -> str:
        lines = ["Tool results:"]
        for r in tool_results:
            if r.get("error"):
                lines.append(f"- {r.get('name')} (id={r.get('tool_use_id')}) ERROR: {r['error']}")
            else:
                lines.append(f"- {r.get('name')} (id={r.get('tool_use_id')}): {r.get('result')}")
        lines.append("Continue the analysis or emit a final answer.")
        return "\n".join(lines)


# Re-exported for ergonomics.
def get_tool_registry() -> Dict[str, Tool]:
    return dict(TOOL_REGISTRY)


def get_tool_by_name(name: str) -> Optional[Tool]:
    return get_tool(name)
