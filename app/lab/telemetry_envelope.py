"""
Normalized runtime event envelope (WS7-T1).

Maps Tracee, Falco, Tetragon, and generic tool output into one schema.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

REQUIRED_ENVELOPE_FIELDS = frozenset(
    {
        "schema_version",
        "source_tool",
        "event_time",
        "severity",
    }
)

SCHEMA_VERSION = "1.0"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_runtime_event(event: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Return (ok, errors) for envelope validation."""
    errors: List[str] = []
    for key in REQUIRED_ENVELOPE_FIELDS:
        if key not in event or event[key] in (None, ""):
            errors.append(f"missing_field:{key}")
    if event.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version_mismatch")
    return (len(errors) == 0, errors)


def base_event(
    *,
    source_tool: str,
    severity: str = "info",
    event_time: Optional[str] = None,
    process: Optional[Dict[str, Any]] = None,
    parent_process: Optional[Dict[str, Any]] = None,
    file_ref: Optional[Dict[str, Any]] = None,
    network: Optional[Dict[str, Any]] = None,
    policy: Optional[Dict[str, Any]] = None,
    raw: Optional[Dict[str, Any]] = None,
    evidence_refs: Optional[List[str]] = None,
) -> Dict[str, Any]:
    evt = {
        "schema_version": SCHEMA_VERSION,
        "source_tool": source_tool,
        "event_time": event_time or utc_now_iso(),
        "severity": severity,
        "process": process or {},
        "parent_process": parent_process or {},
        "file": file_ref or {},
        "network": network or {},
        "policy_match": policy or {},
        "raw_event": raw or {},
        "evidence_file_refs": evidence_refs or [],
    }
    return evt


def normalize_falco_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single JSON line from Falco output if present."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None
    rule = raw.get("rule") or raw.get("output_fields", {}).get("evt.type") or "falco_event"
    sev = str(raw.get("priority") or "notice").lower()
    proc = raw.get("output_fields") or {}
    return base_event(
        source_tool="falco",
        severity=sev,
        process={"name": proc.get("proc.name"), "cmdline": proc.get("proc.cmdline")},
        policy={"rule": rule},
        raw=raw,
    )


def normalize_tracee_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse Tracee json line (best-effort)."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None
    return base_event(
        source_tool="tracee",
        severity=str(raw.get("severity") or "info").lower(),
        process={
            "pid": raw.get("processId") or raw.get("pid"),
            "name": raw.get("processName"),
        },
        raw=raw,
    )


def normalize_tetragon_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None
    proc = raw.get("process_kprobe") or raw.get("process_exec") or {}
    return base_event(
        source_tool="tetragon",
        severity="info",
        process={"pid": proc.get("process", {}).get("pid") if isinstance(proc.get("process"), dict) else None},
        raw=raw,
    )
