import pytest
from hashlib import sha256
from pathlib import Path
from tempfile import NamedTemporaryFile

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.tenancy import get_or_create_demo_tenant
from app.models import Asset
from app.services.auth_service import AuthService
from app.services.demo_seed_service import DemoSeedService
from app.services.sheshnaag_service import SheshnaagService


def make_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return testing_session_local()


@pytest.mark.unit
def test_sheshnaag_intel_overview_and_candidates_bootstrap_from_demo_seed():
    session = make_session()
    DemoSeedService(session).seed()
    session.commit()

    tenant = get_or_create_demo_tenant(session)
    service = SheshnaagService(session)

    overview = service.get_intel_overview(tenant)
    candidates = service.list_candidates(tenant, limit=10)

    assert overview["mission"]["headline"].startswith("Live CVE intelligence")
    assert overview["summary"]["candidate_count"] >= 1
    assert any(item["feed_key"] == "nvd" for item in overview["sources"])

    for src in overview["sources"]:
        assert "is_stale" in src, f"missing is_stale on {src['feed_key']}"
        assert isinstance(src["is_stale"], bool)
        assert "stale_since" in src
        assert "last_error" in src
        assert "recent_item_count_delta" in src
        assert isinstance(src["recent_item_count_delta"], int)

    assert candidates["count"] >= 1
    assert candidates["items"][0]["candidate_score"] >= 0
    assert "factors" in candidates["items"][0]["explainability"]


@pytest.mark.unit
def test_private_tenant_recipe_run_bundle_flow_creates_evidence_provenance_and_ledger():
    session = make_session()
    DemoSeedService(session).seed()
    auth = AuthService(session)
    onboard = auth.onboard_private_tenant(
        tenant_name="Sheshnaag Private",
        tenant_slug="sheshnaag-private",
        admin_email="owner@sheshnaag.local",
        admin_password="supersecure123",
        admin_name="Owner Analyst",
    )
    tenant = auth.resolve_private_tenant(token_data=None, tenant_id=onboard["tenant"]["id"])
    session.add(
        Asset(
            tenant_id=tenant.id,
            name="payments-gateway",
            asset_type="application",
            environment="production",
            criticality="high",
            business_criticality="high",
            installed_software=[{"vendor": "acme", "product": "acme-api-gateway", "version": "7.4.2"}],
        )
    )
    session.commit()

    service = SheshnaagService(session)
    candidates = service.list_candidates(tenant, limit=10)
    candidate = candidates["items"][0]

    assigned = service.assign_candidate(tenant, candidate_id=candidate["id"], analyst_name="Owner Analyst")
    recipe = service.create_recipe(
        tenant,
        candidate_id=candidate["id"],
        name="Gateway validation recipe",
        objective="Validate exploit conditions in a constrained Kali environment.",
        created_by="Owner Analyst",
        content={
            "command": ["bash", "-lc", "echo sheshnaag-validation"],
            "risk_level": "sensitive",
            "requires_acknowledgement": True,
            "network_policy": {"allow_egress_hosts": []},
        },
    )
    approved = service.approve_recipe_revision(tenant, recipe_id=recipe["id"], revision_number=1, reviewer="Lead Reviewer")
    run = service.launch_run(
        tenant,
        recipe_id=recipe["id"],
        revision_number=1,
        analyst_name="Owner Analyst",
        workstation={"hostname": "analyst-mbp", "os_family": "macOS", "architecture": "arm64", "fingerprint": "mbp-local"},
        launch_mode="simulated",
        acknowledge_sensitive=True,
    )
    evidence = service.list_evidence(tenant, run_id=run["id"])
    artifacts = service.list_artifacts(tenant, run_id=run["id"])
    reviewed = service.review_artifact(
        tenant,
        artifact_family="detection",
        artifact_id=artifacts["detections"][0]["id"],
        decision="approved",
        reviewer="Lead Reviewer",
        rationale="Observed evidence supports this detection.",
    )
    feedback = service.add_artifact_feedback(
        tenant,
        artifact_family="detection",
        artifact_id=artifacts["detections"][0]["id"],
        reviewer="Lead Reviewer",
        feedback_type="false_positive",
        note="Needs narrower scoping before external use.",
    )
    provenance = service.get_provenance(tenant, run_id=run["id"])
    ledger = service.get_ledger(tenant)
    disclosure = service.create_disclosure_bundle(
        tenant,
        run_id=run["id"],
        bundle_type="vendor_disclosure",
        title="Gateway validation disclosure bundle",
        signed_by="Owner Analyst",
        confirm_external_export=True,
    )

    assert assigned["assignment_state"] == "assigned"
    assert approved["revisions"][0]["approval_state"] == "approved"
    assert run["state"] in {"completed", "planned", "blocked"}
    assert evidence["count"] >= 1
    assert len(artifacts["detections"]) >= 1
    assert len(artifacts["mitigations"]) >= 1
    assert reviewed["status"] == "approved"
    assert feedback["feedback"][0]["feedback_type"] == "false_positive"
    assert provenance["count"] >= 1
    assert provenance["manifest_summary"]["recipe_revision_id"] == run["recipe_revision_id"]
    assert provenance["manifest_summary"]["acknowledgement"]["acknowledged_by"] == "Owner Analyst"
    assert provenance["manifest_summary"]["acknowledgement"]["text_sha256"]
    assert len(provenance["review_history"]) >= 1
    assert ledger["count"] >= 3
    assert disclosure["status"] == "exported"
    assert Path(disclosure["archive"]["path"]).exists()


@pytest.mark.unit
def test_disclosure_bundle_download_metadata_and_provenance_are_linked():
    session = make_session()
    DemoSeedService(session).seed()
    auth = AuthService(session)
    onboard = auth.onboard_private_tenant(
        tenant_name="Sheshnaag Bundle Tenant",
        tenant_slug="sheshnaag-bundles-private",
        admin_email="bundleowner@sheshnaag.local",
        admin_password="supersecure123",
        admin_name="Bundle Owner",
    )
    tenant = auth.resolve_private_tenant(token_data=None, tenant_id=onboard["tenant"]["id"])
    session.add(
        Asset(
            tenant_id=tenant.id,
            name="erp-api",
            asset_type="application",
            environment="production",
            criticality="critical",
            business_criticality="critical",
            installed_software=[{"vendor": "acme", "product": "acme-api-gateway", "version": "7.4.2"}],
        )
    )
    session.commit()

    service = SheshnaagService(session)
    candidate = service.list_candidates(tenant, limit=1)["items"][0]
    recipe = service.create_recipe(
        tenant,
        candidate_id=candidate["id"],
        name="Disclosure recipe",
        objective="Exercise export packaging.",
        created_by="Bundle Owner",
        content={
            "command": ["bash", "-lc", "echo disclosure"],
            "network_policy": {"allow_egress_hosts": []},
        },
    )
    service.approve_recipe_revision(tenant, recipe_id=recipe["id"], revision_number=1, reviewer="Lead Reviewer")
    run = service.launch_run(
        tenant,
        recipe_id=recipe["id"],
        revision_number=1,
        analyst_name="Bundle Owner",
        workstation={"hostname": "bundle-mbp", "os_family": "macOS", "architecture": "arm64", "fingerprint": "bundle-fp"},
        launch_mode="simulated",
        acknowledge_sensitive=False,
    )
    bundle = service.create_disclosure_bundle(
        tenant,
        run_id=run["id"],
        bundle_type="research_bounty",
        title="Research bounty package",
        signed_by="Bundle Owner",
        confirm_external_export=True,
    )
    archive = service.get_disclosure_bundle_archive(tenant, bundle_id=bundle["id"])
    provenance = service.get_provenance(tenant, run_id=run["id"])

    assert archive["path"].endswith(".zip")
    assert Path(archive["path"]).exists()
    assert any(item["subject_type"] == "disclosure_bundle" for item in provenance["items"])
    assert provenance["export_history"][0]["id"] == bundle["id"]


@pytest.mark.unit
def test_create_recipe_rejects_unsafe_mounts():
    session = make_session()
    DemoSeedService(session).seed()
    tenant = get_or_create_demo_tenant(session)
    service = SheshnaagService(session)
    candidate = service.list_candidates(tenant, limit=1)["items"][0]

    with pytest.raises(ValueError, match="host-sensitive|allowed host path roots"):
        service.create_recipe(
            tenant,
            candidate_id=candidate["id"],
            name="Unsafe recipe",
            objective="Should fail validation.",
            created_by="Demo Analyst",
            content={
                "command": ["bash", "-lc", "echo unsafe"],
                "network_policy": {"allow_egress_hosts": []},
                "mounts": [{"source": "/Users/demo/Documents", "target": "/workspace/input", "read_only": True}],
            },
        )


@pytest.mark.unit
def test_launch_run_transfers_artifact_inputs_into_workspace():
    session = make_session()
    DemoSeedService(session).seed()
    auth = AuthService(session)
    onboard = auth.onboard_private_tenant(
        tenant_name="Sheshnaag Artifact Tenant",
        tenant_slug="sheshnaag-artifact-private",
        admin_email="artifactowner@sheshnaag.local",
        admin_password="supersecure123",
        admin_name="Artifact Owner",
    )
    tenant = auth.resolve_private_tenant(token_data=None, tenant_id=onboard["tenant"]["id"])
    session.add(
        Asset(
            tenant_id=tenant.id,
            name="artifact-api",
            asset_type="application",
            environment="production",
            criticality="high",
            business_criticality="high",
            installed_software=[{"vendor": "acme", "product": "acme-api-gateway", "version": "7.4.2"}],
        )
    )
    session.commit()

    service = SheshnaagService(session)
    candidate = service.list_candidates(tenant, limit=1)["items"][0]

    with NamedTemporaryFile("wb", dir="/tmp", suffix=".bin", delete=False) as handle:
        handle.write(b"sheshnaag-artifact-input")
        source_path = handle.name
    expected_sha256 = sha256(Path(source_path).read_bytes()).hexdigest()

    recipe = service.create_recipe(
        tenant,
        candidate_id=candidate["id"],
        name="Artifact input recipe",
        objective="Exercise artifact transfer.",
        created_by="Artifact Owner",
        content={
            "command": ["bash", "-lc", "echo artifact-transfer"],
            "network_policy": {"allow_egress_hosts": []},
            "artifact_inputs": [
                {
                    "source_path": source_path,
                    "name": "fixture.bin",
                    "sha256": expected_sha256,
                    "destination": "/workspace/inputs/fixture.bin",
                }
            ],
        },
    )
    service.approve_recipe_revision(tenant, recipe_id=recipe["id"], revision_number=1, reviewer="Lead Reviewer")
    run = service.launch_run(
        tenant,
        recipe_id=recipe["id"],
        revision_number=1,
        analyst_name="Artifact Owner",
        workstation={"hostname": "artifact-mbp", "os_family": "macOS", "architecture": "arm64", "fingerprint": "artifact-fp"},
        launch_mode="simulated",
        acknowledge_sensitive=False,
    )

    transfer = (run["manifest"] or {}).get("artifact_transfer") or {}
    assert transfer["status"] == "completed"
    assert transfer["transfers"][0]["status"] == "transferred"
    assert Path(transfer["transfers"][0]["destination"]).exists()
