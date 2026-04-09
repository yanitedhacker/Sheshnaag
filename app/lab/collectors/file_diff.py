"""Filesystem listing / delta hints for workspace paths."""

from __future__ import annotations

from typing import Any, Dict, List

from app.lab.interfaces import Collector

from app.lab.collectors.common import (
    build_evidence_dict,
    collector_error_evidence,
    collector_health_meta,
    synthetic_from_plan,
    truncate_text,
    utc_iso,
)
from app.lab.collectors.runtime import is_executable_guest_context, resolve_container_id, run_in_container

MAX_OUTPUT_BYTES = 400_000
MAX_FILES = 8000


class FileDiffCollector(Collector):
    collector_name = "file_diff"
    collector_version = "1.0.0"

    def collect(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not is_executable_guest_context(run_context=run_context, provider_result=provider_result):
            return [
                synthetic_from_plan(
                    collector_name=self.collector_name,
                    title="Filesystem delta",
                    summary="Synthetic filesystem delta (non-live mode).",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                )
            ]
        cid = resolve_container_id(provider_result)
        assert cid
        plan = provider_result.get("plan") or {}
        workdir = plan.get("workdir") or "/workspace"
        started = utc_iso()
        inner = (
            f"find {workdir} -xdev -type f 2>/dev/null | "
            f"head -n {MAX_FILES + 1} | sort"
        )
        code, out, err = run_in_container(cid, ["sh", "-c", inner], timeout_sec=120)
        ended = utc_iso()
        if code != 0 and not out.strip():
            return [
                collector_error_evidence(
                    collector_name=self.collector_name,
                    title="File listing failed",
                    message=err or f"exit {code}",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                    tool="find",
                )
            ]
        text, trunc = truncate_text(out, MAX_OUTPUT_BYTES)
        paths = [p.strip() for p in text.splitlines() if p.strip()]
        truncated = trunc or len(paths) > MAX_FILES
        if len(paths) > MAX_FILES:
            paths = paths[:MAX_FILES]
        cur_set = set(paths)
        baseline_raw = plan.get("file_manifest_baseline")
        delta: Dict[str, Any]
        if isinstance(baseline_raw, list):
            bset = {str(x).strip() for x in baseline_raw if isinstance(x, str) and str(x).strip()}
            added = sorted(cur_set - bset)
            removed = sorted(bset - cur_set)
            delta = {
                "baseline_path_count": len(bset),
                "added": added,
                "removed": removed,
                "unchanged_count": len(cur_set & bset),
            }
        else:
            delta = {
                "note": "No file_manifest_baseline in recipe/plan; post-run snapshot only (WS6-T4 full delta needs a baseline).",
            }
        payload = {
            "collector": self.collector_name,
            "mode": "live",
            "workdir": workdir,
            "paths": paths,
            "path_count": len(paths),
            "delta": delta,
            "truncated": truncated,
            "stderr": (err or "")[:2000],
            "collector_health": collector_health_meta(
                collector=self.collector_name,
                version=self.collector_version,
                started_at=started,
                ended_at=ended,
                status="ok",
                output_bytes=len(text.encode("utf-8")),
            ),
        }
        summary = f"Listed {len(paths)} files under {workdir}."
        if isinstance(baseline_raw, list):
            summary = (
                f"File delta vs baseline: +{len(delta.get('added', []))} "
                f"-{len(delta.get('removed', []))} unchanged≈{delta.get('unchanged_count', 0)}."
            )
        return [
            build_evidence_dict(
                artifact_kind=self.collector_name,
                title="Filesystem snapshot",
                summary=summary,
                payload=payload,
                capture_started_at=started,
                capture_ended_at=ended,
                collector_name=self.collector_name,
                collector_version=self.collector_version,
                truncated=truncated,
            )
        ]
