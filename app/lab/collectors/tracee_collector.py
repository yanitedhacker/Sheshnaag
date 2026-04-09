"""Tracee integration (optional); normalizes to telemetry envelope."""

from __future__ import annotations

from typing import Any, Dict, List

from app.lab.interfaces import Collector

from app.lab.collectors.common import build_evidence_dict, collector_health_meta, synthetic_from_plan, utc_iso
from app.lab.collectors.runtime import is_executable_guest_context, resolve_container_id, run_in_container
from app.lab.telemetry_envelope import normalize_tracee_line, validate_runtime_event
from app.lab.telemetry_translation import translate_with_enterprise_pack


class TraceeEventsCollector(Collector):
    collector_name = "tracee_events"
    collector_version = "1.0.0"

    def collect(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        plan = provider_result.get("plan") or {}
        tooling_profile = plan.get("tooling_profile") if isinstance(plan.get("tooling_profile"), dict) else {}
        if not bool(tooling_profile.get("tracee_available")):
            return [
                synthetic_from_plan(
                    collector_name=self.collector_name,
                    title="Tracee runtime events",
                    summary="Tracee requested but the selected trusted image is not Tracee-capable.",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                )
            ]
        if not is_executable_guest_context(run_context=run_context, provider_result=provider_result):
            return [
                synthetic_from_plan(
                    collector_name=self.collector_name,
                    title="Tracee runtime events",
                    summary="Synthetic Tracee-style stream (non-live mode).",
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
            ["sh", "-c", "command -v tracee >/dev/null && tracee version 2>&1 || echo MISSING"],
            timeout_sec=20,
        )
        if "MISSING" in (out or "") or code != 0:
            ended = utc_iso()
            payload = {
                "collector": self.collector_name,
                "mode": "skipped",
                "normalized_events": [],
                "collector_health": collector_health_meta(
                    collector=self.collector_name,
                    version=self.collector_version,
                    started_at=started,
                    ended_at=ended,
                    status="skipped",
                    skip_reason="tracee_not_installed",
                    error=(err or out or "")[:2000],
                    tool="tracee",
                ),
            }
            return [
                build_evidence_dict(
                    artifact_kind=self.collector_name,
                    title="Tracee (skipped)",
                    summary="Tracee binary not present in guest.",
                    payload=payload,
                    capture_started_at=started,
                    capture_ended_at=ended,
                    collector_name=self.collector_name,
                    collector_version=self.collector_version,
                )
            ]
        events: List[Dict[str, Any]] = []
        for line in (out or "").splitlines():
            ne = normalize_tracee_line(line)
            if ne:
                ok, _ = validate_runtime_event(ne)
                if ok:
                    events.append(ne)
        translation = translate_with_enterprise_pack(events)
        ended = utc_iso()
        payload = {
            "collector": self.collector_name,
            "mode": "live",
            "normalized_events": translation["events_tagged"],
            "findings": translation["findings"],
            "pack_version": translation["pack_version"],
            "raw_preview": (out or "")[:4000],
            "collector_health": collector_health_meta(
                collector=self.collector_name,
                version=self.collector_version,
                started_at=started,
                ended_at=ended,
                status="ok",
                output_bytes=len((out or "").encode("utf-8")),
                tool="tracee",
            ),
        }
        return [
            build_evidence_dict(
                artifact_kind=self.collector_name,
                title="Tracee runtime events",
                summary=f"Normalized {len(events)} Tracee-style event(s).",
                payload=payload,
                capture_started_at=started,
                capture_ended_at=ended,
                collector_name=self.collector_name,
                collector_version=self.collector_version,
            )
        ]
