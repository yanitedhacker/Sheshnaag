"""Network metadata from guest plus effective policy from manifest."""

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

MAX_OUTPUT_BYTES = 256_000


class NetworkMetadataCollector(Collector):
    collector_name = "network_metadata"
    collector_version = "1.0.0"

    def collect(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        plan = provider_result.get("plan") or {}
        effective = plan.get("effective_network_policy") or {}
        if not is_executable_guest_context(run_context=run_context, provider_result=provider_result):
            started = utc_iso()
            payload = {
                "collector": self.collector_name,
                "mode": "synthetic",
                "effective_network_policy": effective,
                "connections": [],
                "collector_health": collector_health_meta(
                    collector=self.collector_name,
                    version=self.collector_version,
                    started_at=started,
                    ended_at=utc_iso(),
                    status="skipped",
                    skip_reason="non_execute_launch_mode_or_synthetic_fallback",
                ),
            }
            return [
                build_evidence_dict(
                    artifact_kind=self.collector_name,
                    title="Network metadata",
                    summary="Policy context without live socket capture (non-live).",
                    payload=payload,
                    capture_started_at=started,
                    capture_ended_at=payload["collector_health"]["ended_at"],
                    collector_name=self.collector_name,
                    collector_version=self.collector_version,
                )
            ]
        cid = resolve_container_id(provider_result)
        assert cid
        started = utc_iso()
        code, out, err = run_in_container(
            cid,
            ["sh", "-c", "ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || true"],
            timeout_sec=45,
        )
        ended = utc_iso()
        text, trunc = truncate_text(out or "", MAX_OUTPUT_BYTES)
        allow_hosts = list(effective.get("allow_egress_hosts") or plan.get("allow_egress_hosts") or [])
        payload = {
            "collector": self.collector_name,
            "mode": "live",
            "effective_network_policy": effective,
            "allow_egress_hosts": allow_hosts,
            "raw_socket_summary": text,
            "docker_exit_code": code,
            "stderr": (err or "")[:2000],
            "truncated": trunc,
            "collector_health": collector_health_meta(
                collector=self.collector_name,
                version=self.collector_version,
                started_at=started,
                ended_at=ended,
                status="ok" if code == 0 or text.strip() else "error",
                output_bytes=len(text.encode("utf-8")),
                error=None if (code == 0 or text.strip()) else (err or f"exit {code}"),
            ),
        }
        if not text.strip() and code != 0:
            return [
                collector_error_evidence(
                    collector_name=self.collector_name,
                    title="Network metadata capture failed",
                    message=err or f"exit {code}",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                    tool="ss",
                )
            ]
        return [
            build_evidence_dict(
                artifact_kind=self.collector_name,
                title="Network metadata",
                summary="Guest socket summary with policy context.",
                payload=payload,
                capture_started_at=started,
                capture_ended_at=ended,
                collector_name=self.collector_name,
                collector_version=self.collector_version,
                truncated=trunc,
            )
        ]
