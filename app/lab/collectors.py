"""Default collector implementations for Sheshnaag."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List

from app.lab.interfaces import Collector


class SyntheticCollector(Collector):
    """Generate normalized evidence records from the provider plan."""

    def __init__(self, collector_name: str, title: str, summary: str):
        self.collector_name = collector_name
        self._title = title
        self._summary = summary

    def collect(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        payload = {
            "collector": self.collector_name,
            "run_id": run_context.get("run_id"),
            "provider_run_ref": provider_result.get("provider_run_ref"),
            "plan": provider_result.get("plan", {}),
        }
        serialized = json.dumps(payload, sort_keys=True)
        return [
            {
                "artifact_kind": self.collector_name,
                "title": self._title,
                "summary": self._summary,
                "payload": payload,
                "sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
            }
        ]


def default_collectors() -> List[Collector]:
    """Return the default Docker-first evidence collector set."""
    return [
        SyntheticCollector("process_tree", "Process tree snapshot", "Synthetic process execution tree captured from the planned Kali environment."),
        SyntheticCollector("package_inventory", "Package inventory diff", "Version-pinned package inventory before and after the validation path."),
        SyntheticCollector("file_diff", "Filesystem delta", "Observed file and path changes relative to the ephemeral workspace baseline."),
        SyntheticCollector("network_metadata", "Network metadata", "Structured egress metadata aligned to the allowlist policy for the run."),
        SyntheticCollector("service_logs", "Service logs", "Collected application and system log excerpts for the validation window."),
        SyntheticCollector("tracee_events", "Tracee runtime events", "Tracee-style runtime event stream normalized into the Sheshnaag evidence envelope."),
    ]
