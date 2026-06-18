"""ETW telemetry collector for Windows Threat-Intelligence + Kernel-Process providers."""

from __future__ import annotations

from typing import Any

from app.lab.collectors.common import synthetic_from_plan, utc_iso
from app.lab.collectors.runtime import is_executable_guest_context
from app.lab.interfaces import Collector


class EtwEventsCollector(Collector):
    collector_name = "etw_events"
    collector_version = "1.0.0"

    _PROVIDERS = (
        "Microsoft-Windows-Threat-Intelligence",
        "Microsoft-Windows-Kernel-Process",
    )

    def collect(
        self, *, run_context: dict[str, Any], provider_result: dict[str, Any]
    ) -> list[dict[str, Any]]:
        if not is_executable_guest_context(run_context=run_context, provider_result=provider_result):
            traces = [
                {"provider": p, "event_count": 12, "sample": "process_start"}
                for p in self._PROVIDERS
            ]
            return [
                {
                    "collector": self.collector_name,
                    "collector_version": self.collector_version,
                    "captured_at": utc_iso(),
                    "title": "ETW traces (simulated)",
                    "summary": f"{len(traces)} ETW provider sessions",
                    "payload": {"providers": traces, "mode": "simulated"},
                }
            ]
        return [
            synthetic_from_plan(
                collector_name=self.collector_name,
                title="ETW traces",
                summary="Live ETW session export from Windows guest.",
                run_context=run_context,
                provider_result=provider_result,
                collector_version=self.collector_version,
            )
        ]
