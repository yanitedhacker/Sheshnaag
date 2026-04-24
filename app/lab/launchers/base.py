"""Launcher contract for V4 dynamic analysis dispatch.

Each concrete launcher owns one specimen class (PE, ELF, browser, email,
archive, URL). The :class:`Launcher` Protocol defines the single entry
point :meth:`launch` which the :func:`dispatch_launcher` factory resolves
for ``materialize_run_outputs`` in ``app/services/malware_lab_service.py``.

Launchers are intentionally thin:
    * They shell out to real analysis tooling at subprocess boundaries so
      unit tests can patch :mod:`subprocess` without touching disk.
    * They never persist DB rows — rows are materialised by the service
      layer from the :class:`LauncherResult` telemetry.
    * They do not speak to the capability-policy engine — that chokepoint
      is enforced by the caller.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional, Protocol, runtime_checkable


@dataclass
class LauncherResult:
    """Normalised telemetry handed back from every launcher.

    Fields use optional / list types so a launcher that can only capture a
    subset of telemetry (for example, the URL launcher does not produce a
    memory dump) simply leaves the missing fields ``None`` / empty.
    """

    exit_code: int = 0
    duration_ms: int = 0
    pcap_path: Optional[str] = None
    memory_dump_path: Optional[str] = None
    ebpf_events: List[dict] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@runtime_checkable
class Launcher(Protocol):
    """Protocol every launcher implements.

    ``kind`` is the canonical ``Specimen.specimen_kind`` string this
    launcher owns; :func:`dispatch_launcher` uses it as a routing key.
    ``can_handle`` lets a launcher refine the match with metadata (e.g. a
    generic ``file`` specimen whose ``metadata["mime_type"]`` is PE).
    """

    kind: str

    def can_handle(self, specimen_kind: str, metadata: dict) -> bool:
        ...

    def launch(
        self,
        *,
        specimen: Any,
        revision: Any,
        profile: Any,
        run: Any,
        quarantine_path: str,
        egress: Any,
        snapshot_snap: Any,
    ) -> LauncherResult:
        ...


__all__ = ["Launcher", "LauncherResult"]
