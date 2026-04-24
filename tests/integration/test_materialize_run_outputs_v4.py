"""Integration test for the V4 ``materialize_run_outputs`` rewrite.

Validates the full launcher-dispatch → context-managers → runners
pipeline. All upstream modules (egress enforcer, snapshot manager,
Volatility runner, Zeek runner, eBPF tracer, capability policy) are
injected into ``sys.modules`` before the service is imported, so the
integration harness exercises the dispatcher without requiring the
parallel-developed modules to exist on disk.
"""

from __future__ import annotations

import sys
import types
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.malware_lab import (
    AnalysisCase,
    BehaviorFinding,
    DefangAction,
    IndicatorArtifact,
    PreventionArtifact,
    SandboxProfile,
    Specimen,
    SpecimenRevision,
)
from app.models.sheshnaag import EvidenceArtifact, LabRecipe, LabRun, RecipeRevision
from app.models.v2 import Tenant


# Banned values — the V4 rewrite must derive confidence from telemetry.
_BANNED_CONFIDENCES = {0.84, 0.82, 0.88, 0.71}


def _make_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return testing_session()


def _seed_run(session):
    tenant = Tenant(name="V4 Tenant", slug="v4-lab")
    session.add(tenant)
    session.flush()

    specimen = Specimen(
        tenant_id=tenant.id,
        name="binary.exe",
        specimen_kind="file/pe",
        source_type="upload",
        status="quarantined",
        risk_level="critical",
        submitted_by="analyst",
        labels=[],
        metadata_json={"mime_type": "application/x-dosexec"},
    )
    session.add(specimen)
    session.flush()

    revision = SpecimenRevision(
        specimen_id=specimen.id,
        parent_revision_id=None,
        revision_number=1,
        sha256="a" * 64,
        content_ref="quarantine://v4/binary.exe",
        ingest_source="upload",
        quarantine_path="/tmp/sheshnaag_quarantine/v4/binary.exe",
        processing_stages=[],
        static_triage={},
        safe_rendering={},
        metadata_json={"mime_type": "application/x-dosexec"},
    )
    session.add(revision)
    specimen.latest_revision_number = 1
    session.flush()

    profile = SandboxProfile(
        tenant_id=tenant.id,
        name="V4 PE detonation",
        profile_type="file_detonation",
        provider_hint="lima",
        risk_level="critical",
        egress_mode="sinkhole",
        is_default=True,
        config={"detonation_timeout_s": 5, "os_hint": "windows"},
    )
    session.add(profile)
    session.flush()

    case = AnalysisCase(
        tenant_id=tenant.id,
        title="V4 case",
        status="open",
        priority="high",
        analyst_name="V4 Analyst",
        specimen_ids=[specimen.id],
    )
    session.add(case)
    session.flush()

    # A minimum valid recipe + revision so the FK on LabRun resolves.
    recipe = LabRecipe(
        tenant_id=tenant.id,
        name="v4 recipe",
        provider="docker_kali",
        status="approved",
    )
    session.add(recipe)
    session.flush()
    recipe_rev = RecipeRevision(
        recipe_id=recipe.id,
        revision_number=1,
        approval_state="approved",
        content={"command": ["noop"]},
    )
    session.add(recipe_rev)
    session.flush()

    run = LabRun(
        tenant_id=tenant.id,
        recipe_revision_id=recipe_rev.id,
        provider="lima",
        launch_mode="simulated",
        state="completed",
        manifest={
            "analysis_mode": "malware_detonation",
            "specimen_ids": [specimen.id],
            "sandbox_profile_id": profile.id,
            "v3_context": {
                "analysis_mode": "malware_detonation",
                "specimen_ids": [specimen.id],
                "sandbox_profile_id": profile.id,
                "linked_case_ids": [case.id],
                "analyst_name": "V4 Analyst",
            },
        },
    )
    session.add(run)
    session.flush()
    return tenant, specimen, revision, profile, case, run


def _install_upstream_mocks():
    """Install stand-in modules for upstream dependencies.

    Returns the MagicMocks so assertions can inspect call counts.
    """

    snapshot_manager_mock = MagicMock(name="SnapshotManager")
    snapshot_cm = MagicMock()
    snapshot_cm.__enter__ = MagicMock(return_value={"snap_id": "snap-1"})
    snapshot_cm.__exit__ = MagicMock(return_value=False)
    snapshot_manager_mock.return_value.with_snapshot.return_value = snapshot_cm

    egress_enforcer_mock = MagicMock(name="EgressEnforcer")
    egress_instance = MagicMock()
    egress_instance.__enter__ = MagicMock(return_value={"rules": ["sinkhole"]})
    egress_instance.__exit__ = MagicMock(return_value=False)
    egress_enforcer_mock.return_value = egress_instance

    ebpf_tracer_mock = MagicMock(name="EbpfTracer")
    ebpf_tracer_mock.return_value.start.return_value = "sid-1"
    ebpf_tracer_mock.return_value.stop.return_value = [
        {"syscall": "execve", "lolbin": True, "title": "execve LOLBin"},
    ]

    zeek_runner_mock = MagicMock(name="ZeekRunner")
    zeek_runner_mock.return_value.run.return_value = {
        "conn": [{"dst": "evil.example", "proto": "tcp"}],
        "dns": [{"query": "evil.example"}],
    }
    zeek_runner_mock.return_value.extract_indicators.return_value = [
        {"kind": "domain", "value": "evil.example", "unique_c2": True},
        {"kind": "ipv4", "value": "203.0.113.99"},
    ]

    volatility_runner_mock = MagicMock(name="VolatilityRunner")
    volatility_runner_mock.return_value.run.return_value = [
        {"plugin": "malfind", "title": "malfind hit in 4321", "severity": "high"},
        {"plugin": "pslist", "title": "pslist anomaly"},
    ]

    # Publish shim modules into sys.modules so the service's
    # _optional_import sees them.
    egress_mod = types.ModuleType("app.lab.egress_enforcer")
    egress_mod.EgressEnforcer = egress_enforcer_mock
    sys.modules["app.lab.egress_enforcer"] = egress_mod

    snap_mod = types.ModuleType("app.lab.snapshot_manager")
    snap_mod.SnapshotManager = snapshot_manager_mock
    sys.modules["app.lab.snapshot_manager"] = snap_mod

    ebpf_mod = types.ModuleType("app.lab.ebpf_tracer")
    ebpf_mod.EbpfTracer = ebpf_tracer_mock
    sys.modules["app.lab.ebpf_tracer"] = ebpf_mod

    zeek_mod = types.ModuleType("app.lab.zeek_runner")
    zeek_mod.ZeekRunner = zeek_runner_mock
    sys.modules["app.lab.zeek_runner"] = zeek_mod

    vol_mod = types.ModuleType("app.lab.volatility_runner")
    vol_mod.VolatilityRunner = volatility_runner_mock
    sys.modules["app.lab.volatility_runner"] = vol_mod

    return {
        "snapshot_manager": snapshot_manager_mock,
        "snapshot_cm": snapshot_cm,
        "egress_enforcer": egress_enforcer_mock,
        "egress_instance": egress_instance,
        "ebpf_tracer": ebpf_tracer_mock,
        "zeek_runner": zeek_runner_mock,
        "volatility_runner": volatility_runner_mock,
    }


def _uninstall_upstream_mocks():
    for path in [
        "app.lab.egress_enforcer",
        "app.lab.snapshot_manager",
        "app.lab.ebpf_tracer",
        "app.lab.zeek_runner",
        "app.lab.volatility_runner",
    ]:
        sys.modules.pop(path, None)


@pytest.mark.integration
def test_materialize_run_outputs_v4_dispatches_launcher_and_persists_real_payloads(monkeypatch):
    session = _make_session()
    tenant, specimen, revision, profile, case, run = _seed_run(session)
    session.commit()

    mocks = _install_upstream_mocks()

    try:
        # Mock the PE launcher's subprocess so we don't touch real virsh.
        from app.lab.launchers import pe_launcher as pe_mod

        monkeypatch.setattr(pe_mod.shutil, "which", lambda name: None)  # dry-run path

        # Patch dispatch_launcher to return a launcher that emits
        # deterministic telemetry AND records invocation. We still use
        # the real PeLauncher so we exercise the protocol, but override
        # its ``launch`` to return a canned result with pcap + memdump
        # paths so downstream runners engage.
        from app.lab.launchers import pe_launcher as pe_module
        from app.lab.launchers.base import LauncherResult

        launched: list = []

        def fake_launch(self, *, specimen, revision, profile, run, quarantine_path, egress, snapshot_snap):
            launched.append(
                {
                    "specimen": specimen,
                    "egress": egress,
                    "snapshot_snap": snapshot_snap,
                    "quarantine_path": quarantine_path,
                }
            )
            return LauncherResult(
                exit_code=0,
                duration_ms=1234,
                pcap_path="/tmp/sheshnaag/run.pcap",
                memory_dump_path="/tmp/sheshnaag/run.mem",
                ebpf_events=[],
                artifacts=["/tmp/sheshnaag/run.pcap", "/tmp/sheshnaag/run.mem"],
                logs=["dispatched"],
                metadata={"launcher": "pe", "mode": "libvirt"},
            )

        monkeypatch.setattr(pe_module.PeLauncher, "launch", fake_launch)

        # Also spy on CapabilityPolicy — allow via tenant_default.
        from app.services import capability_policy as cap_mod
        from app.services.malware_lab_service import MalwareLabService

        eval_calls: list = []
        original_eval = cap_mod.CapabilityPolicy.evaluate

        def spy_evaluate(self, *, capability, scope, actor):
            eval_calls.append({"capability": capability, "scope": scope, "actor": actor})
            return cap_mod.Decision(permitted=True, reason="test_permit", artifact_id=None)

        monkeypatch.setattr(cap_mod.CapabilityPolicy, "evaluate", spy_evaluate)

        service = MalwareLabService(session)
        result = service.materialize_run_outputs(tenant, run=run)
        session.commit()
    finally:
        _uninstall_upstream_mocks()

    # ---- Assertions -----------------------------------------------------
    assert launched, "launcher.launch must be invoked"
    # Snapshot + egress context managers entered and exited.
    mocks["snapshot_manager"].return_value.with_snapshot.assert_called_once()
    mocks["snapshot_cm"].__enter__.assert_called_once()
    mocks["snapshot_cm"].__exit__.assert_called_once()
    mocks["egress_instance"].__enter__.assert_called_once()
    mocks["egress_instance"].__exit__.assert_called_once()
    # eBPF tracer start/stop pair.
    mocks["ebpf_tracer"].return_value.start.assert_called_once()
    mocks["ebpf_tracer"].return_value.stop.assert_called_once_with("sid-1")
    # Zeek + Volatility engaged on the launcher outputs.
    mocks["zeek_runner"].return_value.run.assert_called_once_with("/tmp/sheshnaag/run.pcap")
    mocks["volatility_runner"].return_value.run.assert_called_once()

    # Capability policy was evaluated with dynamic_detonation.
    assert any(c["capability"] == "dynamic_detonation" for c in eval_calls)

    # Dispatch summary records the launcher invocation.
    assert any(
        d["launcher"] == "PeLauncher" and d["status"] == "executed"
        for d in result["launcher_dispatches"]
    )

    # Row counts non-zero and derived from canned telemetry:
    #  - 2 vol findings (malfind, pslist) + 1 ebpf lolbin event = 3 findings
    #  - 2 zeek indicators (domain, ipv4)
    #  - 1 prevention, 1 defang, 1 evidence row
    assert result["evidence_count"] == 1
    assert result["finding_count"] == 3
    assert result["indicator_count"] == 2
    assert result["prevention_count"] == 1
    assert result["defang_count"] == 1

    # Spot-check DB rows.
    evidence_rows = session.query(EvidenceArtifact).filter_by(run_id=run.id).all()
    assert len(evidence_rows) == 1
    assert evidence_rows[0].artifact_kind == "v4_launcher_telemetry"
    assert evidence_rows[0].collector_name == "v4-launcher-dispatcher"
    assert evidence_rows[0].payload["launcher"] == "PeLauncher"

    finding_rows = session.query(BehaviorFinding).filter_by(run_id=run.id).all()
    indicator_rows = session.query(IndicatorArtifact).filter_by(analysis_case_id=case.id).all()
    prevention_rows = session.query(PreventionArtifact).filter_by(analysis_case_id=case.id).all()
    defang_rows = session.query(DefangAction).filter_by(analysis_case_id=case.id).all()

    # --- Confidence de-hardcoding check --------------------------------
    for row in finding_rows:
        assert row.confidence not in _BANNED_CONFIDENCES, (
            f"BehaviorFinding confidence {row.confidence} matches banned hardcode"
        )
    for row in indicator_rows:
        assert row.confidence not in _BANNED_CONFIDENCES, (
            f"IndicatorArtifact confidence {row.confidence} matches banned hardcode"
        )
    for row in prevention_rows:
        quality = (row.payload or {}).get("quality_score")
        assert quality not in _BANNED_CONFIDENCES, (
            f"PreventionArtifact quality_score {quality} matches banned hardcode"
        )

    # Volatility malfind mapping → 0.93; lolbin ebpf → 0.78.
    malfind_rows = [r for r in finding_rows if "malfind" in (r.finding_type or "")]
    assert malfind_rows and malfind_rows[0].confidence == pytest.approx(0.93)
    ebpf_rows = [r for r in finding_rows if r.finding_type.startswith("ebpf:")]
    assert ebpf_rows and ebpf_rows[0].confidence == pytest.approx(0.78)
    # Unique C2 domain → 0.87.
    c2_rows = [r for r in indicator_rows if r.value == "evil.example"]
    assert c2_rows and c2_rows[0].confidence == pytest.approx(0.87)


@pytest.mark.integration
def test_materialize_run_outputs_v4_skips_cve_validation_runs():
    """When the run is a pure CVE-validation run nothing materialises."""

    session = _make_session()
    tenant, specimen, revision, profile, case, run = _seed_run(session)
    run.manifest = {"analysis_mode": "cve_validation", "specimen_ids": []}
    session.commit()

    _install_upstream_mocks()
    try:
        from app.services.malware_lab_service import MalwareLabService

        result = MalwareLabService(session).materialize_run_outputs(tenant, run=run)
    finally:
        _uninstall_upstream_mocks()

    assert result["evidence_count"] == 0
    assert result["finding_count"] == 0
    assert result["indicator_count"] == 0
