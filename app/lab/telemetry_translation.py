"""Event-to-finding translation (WS7-T5)."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.lab.telemetry_envelope import validate_runtime_event
from app.lab.telemetry_policy_packs import ENTERPRISE_STARTER_RULES


def _severity_rank(sev: str) -> int:
    order = {"critical": 4, "high": 3, "medium": 2, "notice": 2, "warning": 2, "low": 1, "info": 0}
    return order.get(str(sev).lower(), 0)


def events_to_findings(
    events: list[dict[str, Any]], *, max_findings: int = 50
) -> list[dict[str, Any]]:
    """Group normalized events into summarized findings."""
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for evt in events:
        ok, _ = validate_runtime_event(evt)
        if not ok:
            continue
        tool = evt.get("source_tool") or "unknown"
        key = f"{tool}:{evt.get('severity', 'info')}:{evt.get('policy_match', {}).get('rule', 'generic')}"
        buckets[key].append(evt)

    findings: list[dict[str, Any]] = []
    for key, evts in buckets.items():
        top = max(evts, key=lambda e: _severity_rank(str(e.get("severity", "info"))))
        findings.append(
            {
                "finding_id": key[:200],
                "title": f"Telemetry cluster ({len(evts)} events)",
                "severity": top.get("severity", "info"),
                "source_tool": top.get("source_tool"),
                "event_count": len(evts),
                "sample_event_time": top.get("event_time"),
                "linked_raw": [e.get("raw_event") for e in evts[:3]],
                "false_positive_notes": [],
            }
        )
    findings.sort(key=lambda f: _severity_rank(str(f.get("severity", "info"))), reverse=True)
    return findings[:max_findings]


def apply_policy_pack(
    events: list[dict[str, Any]], pack_rules: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Attach policy rule hits to events (lightweight string match)."""
    tagged: list[dict[str, Any]] = []
    for evt in events:
        e = dict(evt)
        cmd = ""
        proc = e.get("process") or {}
        if isinstance(proc, dict):
            cmd = str(proc.get("cmdline") or proc.get("name") or "")
        hits = []
        for rule in pack_rules:
            pats = rule.get("patterns") or {}
            subs = pats.get("process_cmdline_substrings") or []
            if subs and any(s in cmd for s in subs):
                hits.append(rule["id"])
        pol = dict(e.get("policy_match") or {})
        if hits:
            pol["pack_hits"] = hits
        e["policy_match"] = pol
        tagged.append(e)
    return tagged


def translate_with_enterprise_pack(events: list[dict[str, Any]]) -> dict[str, Any]:
    tagged = apply_policy_pack(events, ENTERPRISE_STARTER_RULES)
    return {
        "findings": events_to_findings(tagged),
        "events_tagged": tagged,
        "pack_version": "enterprise_starter@1.0.0",
    }
