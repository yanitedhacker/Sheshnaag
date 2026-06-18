"""Caldera C2 adapter — lab-internal chained ATT&CK replay (egress hard-locked)."""

from __future__ import annotations

from typing import Any


class CalderaAdapter:
    """Minimal Caldera integration surface for purple-team orchestration."""

    def __init__(self, *, base_url: str = "http://127.0.0.1:8888") -> None:
        self.base_url = base_url.rstrip("/")

    def run_operation(self, *, name: str, adversary: str, techniques: list[str]) -> dict[str, Any]:
        return {
            "operation": name,
            "adversary": adversary,
            "base_url": self.base_url,
            "egress_locked": True,
            "techniques": techniques,
            "status": "simulated_complete",
        }
