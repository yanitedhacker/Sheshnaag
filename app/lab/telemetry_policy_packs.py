"""Versioned starter policy packs for runtime telemetry (WS7-T6)."""

from __future__ import annotations

from typing import Any, Dict, List

ENTERPRISE_STARTER_VERSION = "1.0.0"

ENTERPRISE_STARTER_RULES: List[Dict[str, Any]] = [
    {
        "id": "priv_esc_sudo",
        "title": "Privilege-changing execution",
        "patterns": {"process_cmdline_substrings": ["sudo ", "su -", "pkexec"]},
        "severity": "high",
    },
    {
        "id": "suspicious_exec_chain",
        "title": "Shell spawning interpreters",
        "patterns": {"process_cmdline_substrings": ["curl ", "wget ", "bash -c"]},
        "severity": "medium",
    },
    {
        "id": "fileless_indicators",
        "title": "Fileless-style execution hints",
        "patterns": {"process_cmdline_substrings": ["/dev/fd/", "memfd:"]},
        "severity": "high",
    },
    {
        "id": "blocked_egress_signal",
        "title": "Egress policy context",
        "patterns": {"network_policy_only": True},
        "severity": "low",
    },
]


def get_pack(name: str) -> Dict[str, Any]:
    if name == "enterprise_starter":
        return {
            "name": name,
            "version": ENTERPRISE_STARTER_VERSION,
            "rules": list(ENTERPRISE_STARTER_RULES),
        }
    return {"name": name, "version": "0.0.0", "rules": []}
