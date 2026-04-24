"""Launcher registry + :func:`dispatch_launcher` factory.

Each concrete launcher advertises its ``kind`` and a ``can_handle``
predicate. :func:`dispatch_launcher` iterates the registry in a stable,
most-specific-first order and returns the first launcher whose predicate
accepts ``(specimen_kind, metadata)``.

The factory raises :class:`ValueError` for unknown specimen kinds rather
than silently falling back to a default, because the caller
(``materialize_run_outputs``) must make an explicit decision (ignore,
quarantine, require operator approval) when no launcher applies.
"""

from __future__ import annotations

from typing import Any, Callable, List

from app.lab.launchers.archive_launcher import ArchiveLauncher
from app.lab.launchers.base import Launcher, LauncherResult
from app.lab.launchers.browser_launcher import BrowserLauncher
from app.lab.launchers.elf_launcher import ElfLauncher
from app.lab.launchers.email_launcher import EmailLauncher
from app.lab.launchers.pe_launcher import PeLauncher
from app.lab.launchers.url_launcher import UrlLauncher

# Order matters: put format-specific matchers before the generic ``file``
# fallback so a PE-looking ``file`` specimen routes to PeLauncher, not
# ElfLauncher. PeLauncher and ElfLauncher both gate on mime type for the
# generic ``file`` kind.
_FACTORY_ORDER: List[Callable[[], Launcher]] = [
    UrlLauncher,
    EmailLauncher,
    ArchiveLauncher,
    BrowserLauncher,
    PeLauncher,
    ElfLauncher,
]


def available_launchers() -> List[Launcher]:
    """Return a freshly-instantiated launcher list in dispatch order."""

    return [factory() for factory in _FACTORY_ORDER]


def dispatch_launcher(specimen_kind: str, file_meta: dict | None = None) -> Launcher:
    """Resolve ``(specimen_kind, metadata)`` to a concrete launcher.

    Raises :class:`ValueError` when no launcher claims the specimen.
    """

    meta = file_meta or {}
    for launcher in available_launchers():
        if launcher.can_handle(specimen_kind, meta):
            return launcher
    raise ValueError(f"no launcher for specimen_kind={specimen_kind!r}")


__all__ = [
    "ArchiveLauncher",
    "BrowserLauncher",
    "ElfLauncher",
    "EmailLauncher",
    "Launcher",
    "LauncherResult",
    "PeLauncher",
    "UrlLauncher",
    "available_launchers",
    "dispatch_launcher",
]
