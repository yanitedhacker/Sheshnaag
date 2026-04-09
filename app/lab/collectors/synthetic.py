"""Synthetic collectors for non-live modes (tests, simulated runs)."""

from __future__ import annotations

from typing import Any, Dict, List

from app.lab.interfaces import Collector

from app.lab.collectors.common import synthetic_from_plan


class SyntheticCollector(Collector):
    """Generate normalized evidence from the provider plan (non-live)."""

    def __init__(self, collector_name: str, title: str, summary: str, version: str = "1.0.0"):
        self.collector_name = collector_name
        self._title = title
        self._summary = summary
        self.collector_version = version

    def collect(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            synthetic_from_plan(
                collector_name=self.collector_name,
                title=self._title,
                summary=self._summary,
                run_context=run_context,
                provider_result=provider_result,
                collector_version=self.collector_version,
            )
        ]
