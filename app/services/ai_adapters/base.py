"""Protocol and shared helpers for native AI provider adapters (V4)."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Iterator, List, Optional, Protocol, runtime_checkable


# -- Canonical streaming event shapes -----------------------------------------
#
# Every adapter emits a stream of dicts with a "type" key. Consumers (the
# harness and AIAgentLoop) switch on the type. Adapters MUST eventually emit a
# terminal event of type "message_stop" carrying a "stop_reason" ∈ {end_turn,
# tool_use, error, max_tokens}.
#
# Standard event types:
#   {"type": "message_start",  "metadata": {...}}
#   {"type": "text_delta",     "text": "..."}
#   {"type": "tool_use",       "tool_use_id": "...", "name": "...", "input": {...}}
#   {"type": "message_stop",   "stop_reason": "end_turn"|"tool_use"|"error"|"max_tokens",
#                              "usage": {"input_tokens": n, "output_tokens": n},
#                              "raw": {...}}
#   {"type": "error",          "error": "message", "recoverable": false}
# -----------------------------------------------------------------------------


@runtime_checkable
class NativeAIAdapter(Protocol):
    """Contract every native AI provider adapter implements."""

    provider_key: str
    display_name: str
    capabilities: List[str]
    model_label: str

    def health(self) -> Dict[str, Any]:
        """Report configuration + reachability status (read-only).

        Must return at minimum: status, healthy, model, missing_configuration.
        Never raises.
        """
        ...

    def stream(
        self,
        *,
        capability: str,
        prompt: str,
        grounding: Dict[str, Any],
        tools: Optional[List[Dict[str, Any]]] = None,
        cache_key: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Stream adapter events. See module docstring for event shapes."""
        ...


# -- Shared helpers -----------------------------------------------------------

def format_grounding_system_prompt(grounding: Dict[str, Any]) -> str:
    """Render a grounding bundle as a system-prompt preamble.

    All adapters use this to enforce the grounded-only contract without
    duplicating templating logic.
    """
    items = grounding.get("items") or []
    lines = [
        "You are Sheshnaag's grounded analysis AI. Respond ONLY from the supplied"
        " grounding items. Every claim MUST cite the item it came from. If the"
        " grounding is insufficient, say so and stop; do not invent.",
        "",
        f"Grounding items ({len(items)}):",
    ]
    for idx, item in enumerate(items, 1):
        if not isinstance(item, dict):
            lines.append(f"[{idx}] {str(item)[:400]}")
            continue
        label = item.get("label") or item.get("kind") or f"item-{idx}"
        summary = item.get("summary") or item.get("value") or ""
        extra = ""
        if item.get("sha256"):
            extra = f" sha256={item['sha256'][:12]}"
        lines.append(f"[{idx}] {label}{extra}: {str(summary)[:1200]}")
    return "\n".join(lines)


def collect_stream(events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Consume a stream of adapter events into an aggregated result.

    Returns a dict:
        {
          "text": str,            # concatenation of all text_delta pieces
          "tool_uses": [...],     # tool_use events
          "stop_reason": str,     # from the terminal message_stop
          "usage": {...},
          "errors": [...],
        }
    """
    text_parts: List[str] = []
    tool_uses: List[Dict[str, Any]] = []
    errors: List[str] = []
    stop_reason = "end_turn"
    usage: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}

    for ev in events:
        etype = ev.get("type")
        if etype == "text_delta":
            text_parts.append(str(ev.get("text", "")))
        elif etype == "tool_use":
            tool_uses.append({
                "tool_use_id": ev.get("tool_use_id"),
                "name": ev.get("name"),
                "input": ev.get("input", {}),
            })
        elif etype == "message_stop":
            stop_reason = ev.get("stop_reason", stop_reason)
            if ev.get("usage"):
                usage = ev["usage"]
        elif etype == "message_start":
            if ev.get("metadata"):
                metadata = ev["metadata"]
        elif etype == "error":
            errors.append(str(ev.get("error", "unknown error")))
            stop_reason = "error"

    return {
        "text": "".join(text_parts),
        "tool_uses": tool_uses,
        "stop_reason": stop_reason,
        "usage": usage,
        "metadata": metadata,
        "errors": errors,
    }
