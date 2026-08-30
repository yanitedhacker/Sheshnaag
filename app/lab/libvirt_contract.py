"""Shared libvirt guest identity contract."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

DEFAULT_LIBVIRT_DOMAIN = os.getenv(
    "SHESHNAAG_WINDOWS_DOMAIN",
    "sheshnaag-win-detonation",
).strip()
LIBVIRT_URI = os.getenv("SHESHNAAG_LIBVIRT_URI", "qemu:///system").strip()


def resolve_libvirt_domain(*configs: Mapping[str, Any] | None) -> str:
    """Resolve one domain name and reject conflicting aliases."""

    names: set[str] = set()
    for config in configs:
        if not config:
            continue
        for key in ("domain", "vm_name"):
            value = str(config.get(key) or "").strip()
            if value:
                names.add(value)
    if len(names) > 1:
        raise ValueError(
            "Conflicting libvirt domain names: " + ",".join(sorted(names))
        )
    if names:
        return next(iter(names))
    if not DEFAULT_LIBVIRT_DOMAIN:
        raise ValueError("SHESHNAAG_WINDOWS_DOMAIN must not be empty")
    return DEFAULT_LIBVIRT_DOMAIN
