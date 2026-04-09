"""osquery snapshot collector (optional guest binary)."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from app.lab.interfaces import Collector

from app.lab.collectors.common import (
    build_evidence_dict,
    collector_health_meta,
    synthetic_from_plan,
    utc_iso,
)
from app.lab.collectors.runtime import is_executable_guest_context, resolve_container_id, run_in_container

QUERIES = [
    "SELECT pid, name, path FROM processes LIMIT 200;",
    "SELECT name, version FROM deb_packages LIMIT 500;",
    "SELECT path, directory FROM file WHERE directory = '/workspace' LIMIT 500;",
]


class OsquerySnapshotCollector(Collector):
    collector_name = "osquery_snapshot"
    collector_version = "1.0.0"

    def collect(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not is_executable_guest_context(run_context=run_context, provider_result=provider_result):
            return [
                synthetic_from_plan(
                    collector_name=self.collector_name,
                    title="osquery snapshot",
                    summary="osquery snapshot skipped outside execute mode.",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                )
            ]
        cid = resolve_container_id(provider_result)
        assert cid
        started = utc_iso()
        plan = provider_result.get("plan") or {}
        tooling_profile = plan.get("tooling_profile") or {}
        if not bool(tooling_profile.get("osquery_available")):
            ended = utc_iso()
            payload = {
                "collector": self.collector_name,
                "mode": "unavailable",
                "reason": "image_not_osquery_capable",
                "expected_image_profile": "osquery",
                "collector_health": collector_health_meta(
                    collector=self.collector_name,
                    version=self.collector_version,
                    started_at=started,
                    ended_at=ended,
                    status="unavailable",
                    error="Recipe image is not marked osquery-capable.",
                    tool="osqueryi",
                ),
            }
            return [
                build_evidence_dict(
                    artifact_kind=self.collector_name,
                    title="osquery snapshot (unavailable)",
                    summary="osquery snapshot requires an osquery-capable lab image.",
                    payload=payload,
                    capture_started_at=started,
                    capture_ended_at=ended,
                    collector_name=self.collector_name,
                    collector_version=self.collector_version,
                )
            ]
        code, out, err = run_in_container(cid, ["which", "osqueryi"], timeout_sec=15)
        if code != 0 or not out.strip():
            ended = utc_iso()
            payload = {
                "collector": self.collector_name,
                "mode": "unavailable",
                "reason": "osqueryi_not_installed",
                "diagnostics": (err or "")[:2000],
                "collector_health": collector_health_meta(
                    collector=self.collector_name,
                    version=self.collector_version,
                    started_at=started,
                    ended_at=ended,
                    status="unavailable",
                    error=err or "osqueryi not found",
                    tool="osqueryi",
                ),
            }
            return [
                build_evidence_dict(
                    artifact_kind=self.collector_name,
                    title="osquery snapshot (unavailable)",
                    summary="osqueryi not available in guest image.",
                    payload=payload,
                    capture_started_at=started,
                    capture_ended_at=ended,
                    collector_name=self.collector_name,
                    collector_version=self.collector_version,
                )
            ]
        results: List[Dict[str, Any]] = []
        had_error = False
        for q in QUERIES:
            qc, qout, qerr = run_in_container(
                cid,
                ["osqueryi", "--json", q],
                timeout_sec=60,
            )
            if qc != 0:
                had_error = True
            rows: Any = []
            if qout.strip():
                try:
                    rows = json.loads(qout)
                except json.JSONDecodeError:
                    rows = [{"parse_error": True, "raw": qout[:4000]}]
            results.append(
                {
                    "query": q,
                    "exit_code": qc,
                    "rows": rows,
                    "stderr": (qerr or "")[:1000],
                }
            )
        ended = utc_iso()
        payload = {
            "collector": self.collector_name,
            "mode": "live",
            "query_results": results,
            "collector_health": collector_health_meta(
                collector=self.collector_name,
                version=self.collector_version,
                started_at=started,
                ended_at=ended,
                status="error" if had_error else "ok",
                output_bytes=len(json.dumps(results).encode("utf-8")),
                error="One or more curated osquery queries failed." if had_error else None,
                tool="osqueryi",
            ),
        }
        return [
            build_evidence_dict(
                artifact_kind=self.collector_name,
                title="osquery snapshot",
                summary=(
                    f"Ran {len(results)} curated queries."
                    if not had_error
                    else f"Ran {len(results)} curated queries with one or more query failures."
                ),
                payload=payload,
                capture_started_at=started,
                capture_ended_at=ended,
                collector_name=self.collector_name,
                collector_version=self.collector_version,
            )
        ]
