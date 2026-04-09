"""Shared evidence builder helpers for collectors."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_json_sha256(payload: Any) -> str:
    serialized = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def collector_health_meta(
    *,
    collector: str,
    version: str,
    started_at: str,
    ended_at: str,
    status: str,
    output_bytes: int = 0,
    skip_reason: Optional[str] = None,
    error: Optional[str] = None,
    tool: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        t0 = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(ended_at.replace("Z", "+00:00"))
        duration_ms = max(0, int((t1 - t0).total_seconds() * 1000))
    except (TypeError, ValueError):
        duration_ms = 0
    return {
        "collector": collector,
        "version": version,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_ms": duration_ms,
        "output_bytes": output_bytes,
        "status": status,
        "skip_reason": skip_reason,
        "error": error,
        "tool": tool,
    }


def build_evidence_dict(
    *,
    artifact_kind: str,
    title: str,
    summary: str,
    payload: Dict[str, Any],
    storage_path: Optional[str] = None,
    content_type: str = "application/json",
    capture_started_at: Optional[str] = None,
    capture_ended_at: Optional[str] = None,
    collector_name: Optional[str] = None,
    collector_version: Optional[str] = None,
    truncated: bool = False,
) -> Dict[str, Any]:
    serialized = json.dumps(payload, sort_keys=True, default=str)
    byte_size = len(serialized.encode("utf-8"))
    item: Dict[str, Any] = {
        "artifact_kind": artifact_kind,
        "title": title,
        "summary": summary,
        "payload": payload,
        "sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        "content_type": content_type,
        "byte_size": byte_size,
        "truncated": truncated,
    }
    if storage_path:
        item["storage_path"] = storage_path
    if capture_started_at:
        item["capture_started_at"] = capture_started_at
    if capture_ended_at:
        item["capture_ended_at"] = capture_ended_at
    if collector_name:
        item["collector_name"] = collector_name
    if collector_version:
        item["collector_version"] = collector_version
    return item


def synthetic_from_plan(
    *,
    collector_name: str,
    title: str,
    summary: str,
    run_context: Dict[str, Any],
    provider_result: Dict[str, Any],
    collector_version: str = "1.0.0",
) -> Dict[str, Any]:
    started = utc_iso()
    plan = provider_result.get("plan") or {}
    payload = {
        "collector": collector_name,
        "mode": "synthetic",
        "run_id": run_context.get("run_id"),
        "provider_run_ref": provider_result.get("provider_run_ref"),
        "plan": plan,
        "collector_health": collector_health_meta(
            collector=collector_name,
            version=collector_version,
            started_at=started,
            ended_at=utc_iso(),
            status="skipped",
            skip_reason="non_execute_launch_mode_or_synthetic_fallback",
        ),
    }
    return build_evidence_dict(
        artifact_kind=collector_name,
        title=title,
        summary=summary,
        payload=payload,
        capture_started_at=started,
        capture_ended_at=payload["collector_health"]["ended_at"],
        collector_name=collector_name,
        collector_version=collector_version,
    )


def collector_error_evidence(
    *,
    collector_name: str,
    title: str,
    message: str,
    run_context: Dict[str, Any],
    provider_result: Dict[str, Any],
    collector_version: str = "1.0.0",
    tool: Optional[str] = None,
) -> Dict[str, Any]:
    started = utc_iso()
    ended = utc_iso()
    payload = {
        "collector": collector_name,
        "error": True,
        "message": message,
        "run_id": run_context.get("run_id"),
        "provider_run_ref": provider_result.get("provider_run_ref"),
        "collector_health": collector_health_meta(
            collector=collector_name,
            version=collector_version,
            started_at=started,
            ended_at=ended,
            status="error",
            error=message,
            tool=tool,
        ),
    }
    return build_evidence_dict(
        artifact_kind=collector_name,
        title=title,
        summary=message[:500],
        payload=payload,
        capture_started_at=started,
        capture_ended_at=ended,
        collector_name=collector_name,
        collector_version=collector_version,
    )


def truncate_text(text: str, max_bytes: int) -> tuple[str, bool]:
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text, False
    cut = raw[:max_bytes].decode("utf-8", errors="ignore")
    return cut, True
