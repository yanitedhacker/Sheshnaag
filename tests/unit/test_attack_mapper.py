"""Unit tests for deterministic ATT&CK mapping."""

from app.models.malware_lab import BehaviorFinding
from app.services.attack_mapper import AttackMapper


def _finding(finding_type: str, payload: dict, title: str = "Finding") -> BehaviorFinding:
    return BehaviorFinding(
        tenant_id=1,
        analysis_case_id=1,
        run_id=1,
        finding_type=finding_type,
        title=title,
        severity="high",
        confidence=0.9,
        payload=payload,
    )


def test_attack_mapper_maps_volatility_malfind():
    mapped = AttackMapper(None).map_finding(
        _finding("memory:windows.malfind", {"source": "volatility", "plugin": "windows.malfind"})
    )
    assert mapped[0]["technique_id"] == "T1055.012"


def test_attack_mapper_maps_ebpf_ptrace():
    mapped = AttackMapper(None).map_finding(
        _finding("ebpf:ptrace", {"source": "ebpf", "raw": {"syscall": "ptrace"}})
    )
    assert mapped[0]["technique_id"] == "T1055.008"


def test_attack_mapper_maps_shell_execve():
    mapped = AttackMapper(None).map_finding(
        _finding("ebpf:execve", {"source": "ebpf", "raw": {"syscall": "execve", "command": "/bin/bash -lc id"}})
    )
    assert mapped[0]["technique_id"] == "T1059.004"


def test_attack_mapper_maps_dns_beacon():
    mapped = AttackMapper(None).map_finding(
        _finding("suspicious_dns", {"source": "zeek"}, title="Beacon observed")
    )
    assert mapped[0]["technique_id"] == "T1071.004"


def test_attack_mapper_maps_yara_shellcode():
    mapped = AttackMapper(None).map_finding(
        _finding("static:yara", {"source": "yara", "raw": {"rule": "CobaltStrike_Shellcode"}})
    )
    assert mapped[0]["technique_id"] == "T1055"
