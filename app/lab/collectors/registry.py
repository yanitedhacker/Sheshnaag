"""Pluggable collector registry (WS6-T1)."""

from __future__ import annotations

from app.lab.collectors.sysmon import SysmonEventsCollector
from app.lab.collectors.etw import EtwEventsCollector
from app.lab.collectors.falco_collector import FalcoEventsCollector
from app.lab.collectors.file_diff import FileDiffCollector
from app.lab.collectors.network_metadata import NetworkMetadataCollector
from app.lab.collectors.osquery_snapshot import OsquerySnapshotCollector
from app.lab.collectors.package_inventory import PackageInventoryCollector
from app.lab.collectors.pcap import PcapCollector
from app.lab.collectors.process_tree import ProcessTreeCollector
from app.lab.collectors.service_logs import ServiceLogsCollector
from app.lab.collectors.synthetic import SyntheticCollector
from app.lab.collectors.tetragon_collector import TetragonEventsCollector
from app.lab.collectors.tracee_collector import TraceeEventsCollector
from app.lab.interfaces import Collector

COLLECTOR_REGISTRY: dict[str, type[Collector]] = {
    "process_tree": ProcessTreeCollector,
    "package_inventory": PackageInventoryCollector,
    "file_diff": FileDiffCollector,
    "network_metadata": NetworkMetadataCollector,
    "service_logs": ServiceLogsCollector,
    "tracee_events": TraceeEventsCollector,
    "osquery_snapshot": OsquerySnapshotCollector,
    "pcap": PcapCollector,
    "falco_events": FalcoEventsCollector,
    "tetragon_events": TetragonEventsCollector,
    "sysmon_events": SysmonEventsCollector,
    "etw_events": EtwEventsCollector,
}


def instantiate_collectors(names: list[str]) -> list[Collector]:
    """Build collector instances in recipe order (dedupe by first occurrence)."""
    seen: set[str] = set()
    out: list[Collector] = []
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        cls = COLLECTOR_REGISTRY.get(name)
        if cls is None:
            out.append(
                SyntheticCollector(
                    collector_name=name,
                    title=f"Unknown collector {name}",
                    summary="Placeholder synthetic evidence for unrecognized collector name.",
                )
            )
            continue
        out.append(cls())
    return out


def default_collectors() -> list[Collector]:
    """Backward-compatible default set (recipe defaults mirror this list)."""
    default_names = [
        "process_tree",
        "package_inventory",
        "file_diff",
        "network_metadata",
        "service_logs",
    ]
    return instantiate_collectors(default_names)
