"""PCAP capture (opt-in, policy-bound; default disabled)."""

from __future__ import annotations

import os
from typing import Any, Dict, List

from app.lab.interfaces import Collector

from app.lab.collectors.common import build_advanced_telemetry_evidence, build_evidence_dict, collector_health_meta, utc_iso
from app.lab.collectors.runtime import env_flag_enabled, is_executable_guest_context, run_in_guest


class PcapCollector(Collector):
    collector_name = "pcap"
    collector_version = "1.0.0"

    def collect(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        started = utc_iso()
        plan = provider_result.get("plan") or {}
        provider_name = str(plan.get("provider") or run_context.get("provider") or "")
        if provider_name != "lima":
            ended = utc_iso()
            return [
                build_advanced_telemetry_evidence(
                    artifact_kind=self.collector_name,
                    title="PCAP disabled",
                    summary="PCAP capture is restricted to secure-mode Lima runs in v2.",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                    tool="tcpdump",
                    mode="skipped",
                    normalized_events=[],
                    findings=[],
                    started_at=started,
                    ended_at=ended,
                    status="skipped",
                    skip_reason="secure_mode_only",
                    supported=False,
                    support_reason="PCAP capture is restricted to secure-mode Lima runs.",
                    storage_eligible=False,
                    contains_raw_payload=False,
                    sensitivity={
                        "classification": "restricted",
                        "external_export_requires_confirmation": True,
                    },
                )
            ]
        if not env_flag_enabled("SHESHNAAG_ENABLE_PCAP", default=False):
            ended = utc_iso()
            payload = {
                "collector": self.collector_name,
                "mode": "disabled",
                "collector_health": collector_health_meta(
                    collector=self.collector_name,
                    version=self.collector_version,
                    started_at=started,
                    ended_at=ended,
                    status="skipped",
                    skip_reason="feature_flag_off",
                ),
            }
            return [
                build_evidence_dict(
                    artifact_kind=self.collector_name,
                    title="PCAP capture disabled",
                    summary="Set SHESHNAAG_ENABLE_PCAP=1 to evaluate PCAP (security review required).",
                    payload=payload,
                    capture_started_at=started,
                    capture_ended_at=ended,
                    collector_name=self.collector_name,
                    collector_version=self.collector_version,
                )
            ]
        if run_context.get("launch_mode") != "execute":
            ended = utc_iso()
            payload = {
                "collector": self.collector_name,
                "mode": "skipped",
                "collector_health": collector_health_meta(
                    collector=self.collector_name,
                    version=self.collector_version,
                    started_at=started,
                    ended_at=ended,
                    status="skipped",
                    skip_reason="non_execute_mode",
                ),
            }
            return [
                build_evidence_dict(
                    artifact_kind=self.collector_name,
                    title="PCAP skipped",
                    summary="PCAP requires execute launch mode in secure mode.",
                    payload=payload,
                    capture_started_at=started,
                    capture_ended_at=ended,
                    collector_name=self.collector_name,
                    collector_version=self.collector_version,
                )
            ]
        max_sec = int(os.environ.get("SHESHNAAG_PCAP_MAX_SECONDS", "5"))
        max_sec = max(1, min(max_sec, 30))
        byte_limit = max(16384, min(int(os.environ.get("SHESHNAAG_PCAP_MAX_BYTES", "65536")), 524288))
        packet_limit = max(1, min(int(os.environ.get("SHESHNAAG_PCAP_PACKET_LIMIT", "20")), 200))
        code = 0
        out = ""
        err = ""
        session_command = (
            "command -v tcpdump >/dev/null && "
            f"timeout {max_sec} tcpdump -c {packet_limit} -w - 2>/dev/null | head -c {byte_limit} | base64 || true"
        )
        code, out, err = run_in_guest(
            provider_result,
            ["sh", "-lc", session_command],
            timeout_sec=max_sec + 15,
        )
        ended = utc_iso()
        preview = (out or "")[:8000]
        status = "ok" if preview.strip() else "degraded"
        return [
            build_advanced_telemetry_evidence(
                artifact_kind=self.collector_name,
                title="PCAP capture",
                summary=(
                    "Bounded PCAP capture session completed."
                    if preview.strip()
                    else "PCAP session ran but returned no bounded capture preview."
                ),
                run_context=run_context,
                provider_result=provider_result,
                collector_version=self.collector_version,
                tool="tcpdump",
                mode="live" if preview.strip() else "degraded",
                normalized_events=[],
                findings=[],
                started_at=started,
                ended_at=ended,
                command=session_command,
                raw_preview=preview,
                stderr_preview=(err or "")[:2000],
                exit_code=code,
                status=status,
                skip_reason=None if preview.strip() else "tcpdump_unavailable_or_empty",
                error=(err or "")[:2000] or None,
                event_limit=packet_limit,
                byte_limit=byte_limit,
                time_limit_seconds=max_sec,
                truncated=len(out or "") >= 8000,
                supported=True,
                support_reason="PCAP is enabled only for secure-mode Lima runs.",
                storage_eligible=False,
                contains_raw_payload=bool(preview.strip()),
                sensitivity={
                    "classification": "restricted",
                    "external_export_requires_confirmation": True,
                    "requires_operator_review": True,
                },
                extra={
                    "pcap_base64_preview": preview,
                    "secure_mode_only": True,
                    "note": "Bounded capture; fuller PCAP workflows remain intentionally out of scope.",
                },
            )
        ]
