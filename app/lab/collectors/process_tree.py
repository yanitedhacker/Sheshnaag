"""Process tree collector."""

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

MAX_OUTPUT_BYTES = 512_000


class ProcessTreeCollector(Collector):
    collector_name = "process_tree"
    collector_version = "1.0.0"

    def collect(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not is_executable_guest_context(run_context=run_context, provider_result=provider_result):
            return [
                synthetic_from_plan(
                    collector_name=self.collector_name,
                    title="Process tree snapshot",
                    summary="Synthetic process execution tree (non-live mode).",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                )
            ]
        cid = resolve_container_id(provider_result)
        assert cid
        started = utc_iso()
        code, out, err = run_in_container(
            cid,
            [
                "sh",
                "-c",
                "ps -eo pid=,ppid=,args= --no-headers 2>/dev/null | head -n 4000",
            ],
            timeout_sec=60,
        )
        ended = utc_iso()
        if code != 0:
            return [
                collector_error_evidence(
                    collector_name=self.collector_name,
                    title="Process tree capture failed",
                    message=err or f"exit {code}",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                    tool="ps",
                )
            ]
        text, trunc = truncate_text(out, MAX_OUTPUT_BYTES)
        rows: List[Dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            try:
                pid = int(parts[0].strip())
                ppid = int(parts[1].strip())
            except ValueError:
                continue
            rows.append({"pid": pid, "ppid": ppid, "cmd": parts[2].strip()})
        health = collector_health_meta(
            collector=self.collector_name,
            version=self.collector_version,
            started_at=started,
            ended_at=ended,
            status="ok",
            output_bytes=len(text.encode("utf-8")),
        )
        payload = {
            "collector": self.collector_name,
            "mode": "live",
            "processes": rows,
            "truncated": trunc,
            "stderr": (err or "")[:2000],
            "collector_health": health,
        }
        return [
            build_evidence_dict(
                artifact_kind=self.collector_name,
                title="Process tree snapshot",
                summary=f"Captured {len(rows)} process rows from guest.",
                payload=payload,
                capture_started_at=started,
                capture_ended_at=ended,
                collector_name=self.collector_name,
                collector_version=self.collector_version,
                truncated=trunc,
            )
        ]
