"""Falco integration (optional)."""

from __future__ import annotations

import os
from typing import Any, Dict, List

from app.lab.interfaces import Collector

from app.lab.collectors.common import build_advanced_telemetry_evidence, synthetic_from_plan, utc_iso
from app.lab.collectors.runtime import env_flag_enabled, is_executable_guest_context, run_in_guest
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
        started = utc_iso()
        time_limit = max(3, min(int(os.environ.get("SHESHNAAG_FALCO_CAPTURE_SECONDS", "6")), 20))
        event_limit = max(10, min(int(os.environ.get("SHESHNAAG_FALCO_EVENT_LIMIT", "60")), 200))
        code, version_out, version_err = run_in_guest(
            provider_result,
            ["sh", "-lc", "command -v falco >/dev/null && falco --version 2>&1 || echo MISSING"],
            timeout_sec=20,
        )
        pack = get_pack("enterprise_starter")
        if "MISSING" in (version_out or ""):
            ended = utc_iso()
            return [
                build_advanced_telemetry_evidence(
                    artifact_kind=self.collector_name,
                    title="Falco (skipped)",
                    summary="Falco not present in guest.",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                    tool="falco",
                    mode="skipped",
                    normalized_events=[],
                    findings=[],
                    started_at=started,
                    ended_at=ended,
                    status="skipped",
                    skip_reason="falco_not_installed",
                    error=(version_err or version_out or "")[:2000],
                    time_limit_seconds=time_limit,
                    event_limit=event_limit,
                    supported=False,
                    support_reason="Falco binary not present in guest.",
                    extra={
                        "policy_pack": pack["name"],
                        "policy_pack_version": pack["version"],
                    },
                )
            ]
        session_command = (
            f"tmp=$(mktemp); "
            f"(timeout {time_limit} sh -lc 'falco -A -o json_output=true -o stdout_output.enabled=true "
            "-o syslog_output.enabled=false -o file_output.enabled=false 2>/dev/null' || true) >\"$tmp\" 2>/dev/null; "
            f"head -n {event_limit} \"$tmp\"; "
            "rm -f \"$tmp\""
        )
        code, out, err = run_in_guest(
            provider_result,
            ["sh", "-lc", session_command],
            timeout_sec=time_limit + 20,
        )
        events: List[Dict[str, Any]] = []
        for line in (out or "").splitlines():
            ne = normalize_falco_line(line)
            if ne:
                ok, _ = validate_runtime_event(ne)
                if ok:
                    events.append(ne)
        translation = translate_with_enterprise_pack(events)
        ended = utc_iso()
        state = "ok" if events else "degraded"
        return [
            build_advanced_telemetry_evidence(
                artifact_kind=self.collector_name,
                title="Falco events",
                summary=(
                    f"Falco bounded session normalized {len(events)} JSON line(s)."
                    if events
                    else "Falco session ran but emitted no normalized events."
                ),
                run_context=run_context,
                provider_result=provider_result,
                collector_version=self.collector_version,
                tool="falco",
                mode="live" if events else "degraded",
                normalized_events=translation["events_tagged"],
                findings=translation["findings"],
                started_at=started,
                ended_at=ended,
                command=session_command,
                raw_preview=(out or "")[:4000],
                stderr_preview=(err or version_err or "")[:2000],
                exit_code=code,
                status=state,
                skip_reason=None if events else "live_session_empty",
                time_limit_seconds=time_limit,
                event_limit=event_limit,
                supported=True,
                support_reason="Falco session executed inside the guest.",
                extra={
                    "policy_pack": pack["name"],
                    "policy_pack_version": pack["version"],
                },
            )
        ]
