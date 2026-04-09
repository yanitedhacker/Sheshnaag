"""PCAP capture (opt-in, policy-bound; default disabled)."""

from __future__ import annotations

import os
from typing import Any, Dict, List

from app.lab.interfaces import Collector

from app.lab.collectors.common import build_evidence_dict, collector_health_meta, utc_iso
from app.lab.collectors.runtime import env_flag_enabled, is_executable_guest_context, resolve_container_id, run_in_container


class PcapCollector(Collector):
    collector_name = "pcap"
    collector_version = "1.0.0"

    def collect(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        started = utc_iso()
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
        if not is_executable_guest_context(run_context=run_context, provider_result=provider_result):
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
                    summary="PCAP requires execute launch mode with Docker.",
                    payload=payload,
                    capture_started_at=started,
                    capture_ended_at=ended,
                    collector_name=self.collector_name,
                    collector_version=self.collector_version,
                )
            ]
        cid = resolve_container_id(provider_result)
        assert cid
        max_sec = int(os.environ.get("SHESHNAAG_PCAP_MAX_SECONDS", "5"))
        max_sec = max(1, min(max_sec, 30))
        code, out, err = run_in_container(
            cid,
            ["sh", "-c", f"command -v tcpdump >/dev/null && tcpdump -c 20 -w - -G {max_sec} 2>/dev/null | head -c 65536 | base64 -w0 || true"],
            timeout_sec=max_sec + 10,
        )
        ended = utc_iso()
        payload = {
            "collector": self.collector_name,
            "mode": "live",
            "note": "Bounded capture; full PCAP requires NET_RAW and security approval.",
            "exit_code": code,
            "pcap_base64_preview": (out or "")[:8000],
            "stderr": (err or "")[:2000],
            "collector_health": collector_health_meta(
                collector=self.collector_name,
                version=self.collector_version,
                started_at=started,
                ended_at=ended,
                status="ok" if out.strip() else "skipped",
                skip_reason=None if out.strip() else "tcpdump_unavailable_or_empty",
                output_bytes=len((out or "").encode("utf-8")),
                tool="tcpdump",
            ),
        }
        return [
            build_evidence_dict(
                artifact_kind=self.collector_name,
                title="PCAP capture",
                summary="Bounded PCAP sample or skip if tcpdump unavailable.",
                payload=payload,
                capture_started_at=started,
                capture_ended_at=ended,
                collector_name=self.collector_name,
                collector_version=self.collector_version,
                truncated=len(out or "") >= 8000,
            )
        ]
