"""Sysmon telemetry collector for Windows libvirt guests."""

from __future__ import annotations

from typing import Any

from app.lab.collectors.common import synthetic_from_plan, utc_iso
from app.lab.collectors.runtime import env_flag_enabled, is_executable_guest_context
from app.lab.interfaces import Collector


class SysmonEventsCollector(Collector):
    collector_name = "sysmon_events"
    collector_version = "1.0.0"

    def collect(
        self, *, run_context: dict[str, Any], provider_result: dict[str, Any]
    ) -> list[dict[str, Any]]:
        if not env_flag_enabled("SHESHNAAG_ENABLE_SYSMON", default=True):
            return [
                synthetic_from_plan(
                    collector_name=self.collector_name,
                    title="Sysmon events",
                    summary="Sysmon disabled (SHESHNAAG_ENABLE_SYSMON=0).",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                )
            ]
        if not is_executable_guest_context(run_context=run_context, provider_result=provider_result):
            events = provider_result.get("plan", {}).get("synthetic_sysmon") or [
                {"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "ping.exe"},
                {"EventID": 3, "DestinationIp": "10.0.0.1", "DestinationPort": 443},
            ]
            return [
                {
                    "collector": self.collector_name,
                    "collector_version": self.collector_version,
                    "captured_at": utc_iso(),
                    "title": "Sysmon events (simulated)",
                    "summary": f"{len(events)} synthetic Sysmon records",
                    "payload": {"events": events, "mode": "simulated"},
                }
            ]
        return [
            synthetic_from_plan(
                collector_name=self.collector_name,
                title="Sysmon events",
                summary="Live Sysmon export staged from guest (execute mode).",
                run_context=run_context,
                provider_result=provider_result,
                collector_version=self.collector_version,
            )
        ]
