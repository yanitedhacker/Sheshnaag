"""Tests for disclosure attachment dispositions and redaction controls."""

from __future__ import annotations

import json
import zipfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.sheshnaag import EvidenceArtifact, LabRecipe, LabRun, RecipeRevision
from app.models.v2 import Tenant
from app.services import sheshnaag_service as service_module
from app.services.sheshnaag_service import SheshnaagService


def test_bundle_excludes_raw_logs_and_redacts_included_payloads(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    monkeypatch.setattr(service_module.settings, "signing_key_dir", str(tmp_path / "keys"))

    tenant = Tenant(slug="export-controls", name="Export Controls")
    session.add(tenant)
    session.flush()
    recipe = LabRecipe(
        tenant_id=tenant.id,
        name="Export recipe",
        provider="docker_kali",
        current_revision_number=1,
    )
    session.add(recipe)
    session.flush()
    revision = RecipeRevision(
        recipe_id=recipe.id,
        revision_number=1,
        approval_state="approved",
        content={},
    )
    session.add(revision)
    session.flush()
    run = LabRun(
        tenant_id=tenant.id,
        recipe_revision_id=revision.id,
        state="completed",
        provider="docker_kali",
        manifest={},
    )
    session.add(run)
    session.flush()
    raw_log = EvidenceArtifact(
        run_id=run.id,
        artifact_kind="service_logs",
        title="Raw service log",
        summary="Raw log data",
        storage_path="/internal/tenant/raw.log",
        payload={"authorization": "Bearer raw-secret"},
    )
    process_tree = EvidenceArtifact(
        run_id=run.id,
        artifact_kind="process_tree",
        title="Process tree",
        summary="Normalized process evidence",
        storage_path="/internal/tenant/process.json",
        payload={
            "process": "sample",
            "api_key": "sensitive-value",
            "nested": {"password": "not-for-export", "pid": 42},
        },
    )
    session.add_all([raw_log, process_tree])
    session.commit()

    service = SheshnaagService(session)
    service.export_root = tmp_path / "exports"
    bundle = service.create_disclosure_bundle(
        tenant,
        run_id=run.id,
        bundle_type="vendor_disclosure",
        title="Controlled bundle",
        signed_by="release-reviewer",
        attachment_policy={"include_raw_logs": False},
        confirm_external_export=True,
    )

    inventory = {
        row["evidence_id"]: row
        for row in bundle["manifest"]["attachment_inventory"]
    }
    assert inventory[raw_log.id]["disposition"] == "excluded_by_policy"
    assert inventory[process_tree.id]["disposition"] == "included_redacted"
    assert all("storage_path" not in row for row in bundle["manifest"]["evidence"])

    with zipfile.ZipFile(bundle["archive"]["path"]) as archive:
        names = set(archive.namelist())
        assert f"evidence/evidence-{raw_log.id}.json" not in names
        included = json.loads(
            archive.read(f"evidence/evidence-{process_tree.id}.json")
        )
        assert included["payload"]["process"] == "sample"
        assert included["payload"]["api_key"] == "[REDACTED]"
        assert included["payload"]["nested"] == {
            "password": "[REDACTED]",
            "pid": 42,
        }

    automatic_paths = {
        item["path"]
        for item in bundle["manifest"]["redaction_log"]["automatic"]
    }
    assert automatic_paths == {
        f"evidence.{process_tree.id}.payload.api_key",
        f"evidence.{process_tree.id}.payload.nested.password",
    }

    with pytest.raises(ValueError, match="attachment_policy_boolean_required"):
        service._prepare_export_evidence(
            bundle_type="vendor_disclosure",
            evidence_rows=[raw_log],
            attachment_policy={"include_raw_logs": "false"},
        )
