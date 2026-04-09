"""Falco integration (optional)."""

from __future__ import annotations

from typing import Any, Dict, List

from app.lab.interfaces import Collector

from app.lab.collectors.common import build_evidence_dict, collector_health_meta, synthetic_from_plan, utc_iso
from app.lab.collectors.runtime import env_flag_enabled, is_executable_guest_context, resolve_container_id, run_in_container
from app.lab.telemetry_envelope import normalize_falco_line, validate_runtime_event
from app.lab.telemetry_policy_packs import get_pack
from app.lab.telemetry_translation import translate_with_enterprise_pack


class FalcoEventsCollector(Collector):
    collector_name = "falco_events"
    collector_version = "1.0.0"

    def collect(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not env_flag_enabled("SHESHNAAG_ENABLE_FALCO", default=False):
            return [
                synthetic_from_plan(
                    collector_name=self.collector_name,
                    title="Falco events",
                    summary="Falco disabled (SHESHNAAG_ENABLE_FALCO).",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                )
            ]
        if not is_executable_guest_context(run_context=run_context, provider_result=provider_result):
            return [
                synthetic_from_plan(
                    collector_name=self.collector_name,
                    title="Falco events",
                    summary="Synthetic Falco placeholder (non-live mode).",
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
            ["sh", "-c", "command -v falco >/dev/null && falco --version 2>&1 || echo MISSING"],
            timeout_sec=20,
        )
        pack = get_pack("enterprise_starter")
        if "MISSING" in (out or ""):
            ended = utc_iso()
            payload = {
                "collector": self.collector_name,
                "mode": "skipped",
                "policy_pack": pack["name"],
                "policy_pack_version": pack["version"],
                "normalized_events": [],
                "collector_health": collector_health_meta(
                    collector=self.collector_name,
                    version=self.collector_version,
                    started_at=started,
                    ended_at=ended,
                    status="skipped",
                    skip_reason="falco_not_installed",
                    error=(err or out or "")[:2000],
                    tool="falco",
                ),
            }
            return [
                build_evidence_dict(
                    artifact_kind=self.collector_name,
                    title="Falco (skipped)",
                    summary="Falco not present in guest.",
                    payload=payload,
                    capture_started_at=started,
                    capture_ended_at=ended,
                    collector_name=self.collector_name,
                    collector_version=self.collector_version,
                )
            ]
        events: List[Dict[str, Any]] = []
        for line in (out or "").splitlines():
            ne = normalize_falco_line(line)
            if ne:
                ok, _ = validate_runtime_event(ne)
                if ok:
                    events.append(ne)
        translation = translate_with_enterprise_pack(events)
        ended = utc_iso()
        payload = {
            "collector": self.collector_name,
            "mode": "live",
            "policy_pack": pack["name"],
            "policy_pack_version": pack["version"],
            "normalized_events": translation["events_tagged"],
            "findings": translation["findings"],
            "raw_preview": (out or "")[:4000],
            "collector_health": collector_health_meta(
                collector=self.collector_name,
                version=self.collector_version,
                started_at=started,
                ended_at=ended,
                status="ok",
                output_bytes=len((out or "").encode("utf-8")),
                tool="falco",
            ),
        }
        return [
            build_evidence_dict(
                artifact_kind=self.collector_name,
                title="Falco events",
                summary=f"Falco probe; normalized {len(events)} JSON line(s).",
                payload=payload,
                capture_started_at=started,
                capture_ended_at=ended,
                collector_name=self.collector_name,
                collector_version=self.collector_version,
            )
        ]
