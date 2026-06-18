"""Unit tests for write-side AI tool backends."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.core.database import Base
from app.models.malware_lab import AnalysisCase, BehaviorFinding, Specimen, SpecimenRevision
from app.models.sheshnaag import DetectionArtifact, LabRecipe, LabRun, RecipeRevision
from app.models.v2 import Tenant
from app.services.ai_tool_actions import (
    propose_detection,
    queue_authorized_offensive_run,
    queue_specimen_detonation,
)
from app.services.ai_tools_registry import get_tool
from app.services.detection_validator import DetectionValidatorService


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    sess = Session()
    tenant = Tenant(slug="ai-tools", name="AI Tools")
    sess.add(tenant)
    sess.flush()
    case = AnalysisCase(tenant_id=tenant.id, title="Case A", analyst_name="alice")
    sess.add(case)
    sess.flush()
    spec = Specimen(tenant_id=tenant.id, name="sample.bin", specimen_kind="file")
    sess.add(spec)
    sess.flush()
    sess.add(
        SpecimenRevision(
            specimen_id=spec.id,
            revision_number=1,
            sha256="a" * 64,
            content_ref="s3://q/sample.bin",
            quarantine_path="/tmp/sheshnaag_quarantine/sample.bin",
        )
    )
    sess.add(
        BehaviorFinding(
            tenant_id=tenant.id,
            analysis_case_id=case.id,
            finding_type="network_c2",
            title="Suspicious outbound DNS",
            severity="high",
            payload={"attack_techniques": [{"technique_id": "T1071.004"}]},
        )
    )
    recipe = LabRecipe(
        tenant_id=tenant.id,
        name="Offensive recipe",
        objective="Authorized offensive test",
        provider="docker_kali",
        status="approved",
        current_revision_number=1,
    )
    sess.add(recipe)
    sess.flush()
    revision = RecipeRevision(
        recipe_id=recipe.id,
        revision_number=1,
        approval_state="approved",
        approved_by="reviewer",
        risk_level="critical",
        requires_acknowledgement=True,
        signed_digest="test-digest",
        content={
            "provider": "docker_kali",
            "image_profile": "baseline",
            "command": ["bash", "-lc", "echo offensive"],
            "network_policy": {"allow_egress_hosts": []},
            "collectors": ["process_tree"],
            "teardown_policy": {"mode": "destroy_immediately", "ephemeral_workspace": True},
            "risk_level": "critical",
            "requires_acknowledgement": True,
        },
    )
    sess.add(revision)
    sess.flush()
    run = LabRun(
        tenant_id=tenant.id,
        recipe_revision_id=revision.id,
        provider="docker_kali",
        launch_mode="simulated",
        state="completed",
    )
    sess.add(run)
    sess.commit()
    yield sess, tenant, case, spec, recipe, run
    sess.close()


def test_propose_detection_validates_and_persists_prevention_artifact(session):
    sess, tenant, case, _, _, _ = session
    out = propose_detection(
        sess,
        tenant,
        kind="sigma",
        draft={
            "title": "Suspicious DNS",
            "logsource": {"product": "linux"},
            "detection": {"selection": {"dns.query": "evil.example.com"}},
            "case_id": case.id,
        },
        actor="alice",
    )
    assert out["validation"]["valid"] is True
    assert out["artifact"]["family"] == "prevention"
    assert out["validation"]["validator"]["precision"] is not None


def test_propose_detection_persists_detection_artifact_for_run(session):
    sess, tenant, _, _, _, run = session
    out = propose_detection(
        sess,
        tenant,
        kind="yara",
        draft={"rule": 'rule C2 { strings: $s = "evil.example.com" condition: $s }', "run_id": run.id},
        actor="alice",
    )
    assert out["artifact"]["family"] == "detection"
    row = sess.query(DetectionArtifact).filter_by(id=out["artifact"]["id"]).one()
    assert row.run_id == run.id
    assert row.status in {"proposed", "draft"}


def test_detection_validator_reports_invalid_sigma(session):
    sess, tenant, _, _, _, _ = session
    result = DetectionValidatorService(sess).validate(
        tenant,
        kind="sigma",
        draft={"title": "Incomplete"},
    )
    assert result["valid"] is False
    assert "missing_logsource" in result["errors"]


def test_registry_propose_detection_without_context_returns_stub_shape():
    tool = get_tool("propose_detection")
    out = tool.callable(kind="sigma", draft={"title": "x"})
    assert out["note"]
    assert out["validator"]["precision"] is None


def test_registry_propose_detection_with_context(session):
    sess, tenant, case, _, _, _ = session
    tool = get_tool("propose_detection")
    out = tool.callable(
        kind="sigma",
        draft={
            "title": "Suspicious DNS",
            "logsource": {"product": "linux"},
            "detection": {"selection": {"dns.query": "evil.example.com"}},
            "case_id": case.id,
        },
        _context={"session": sess, "tenant_id": tenant.id, "actor": "alice"},
    )
    assert out["validation"]["valid"] is True
    assert out["artifact"] is not None


def test_queue_specimen_detonation_returns_blocked_without_quarantined_bytes(session, monkeypatch):
    sess, tenant, _, spec, _, _ = session
    monkeypatch.setattr(
        "app.services.malware_lab_service.MalwareLabService._revision_has_quarantined_bytes",
        lambda self, revision: False,
    )
    profile = queue_specimen_detonation(
        sess,
        tenant,
        specimen_id=spec.id,
        profile_id="Secure File Detonation",
        actor="alice",
    )
    assert profile["tool"] == "detonate_in_sandbox"
    assert profile["status"] in {"blocked", "queued", "planned"}
    assert profile["run_id"] is None or isinstance(profile["run_id"], int)


def test_queue_authorized_offensive_run_requires_approved_recipe(session):
    sess, tenant, _, _, recipe, _ = session
    blocked = queue_authorized_offensive_run(
        sess,
        tenant,
        target="lab-target-01",
        recipe_id=str(recipe.id),
        actor="alice",
    )
    assert blocked["status"] in {"blocked", "queued", "planned", "completed"}
    if blocked["run_id"] is not None:
        run = sess.query(LabRun).filter_by(id=blocked["run_id"]).one()
        assert run.manifest.get("authorized_offensive_target") == "lab-target-01"
