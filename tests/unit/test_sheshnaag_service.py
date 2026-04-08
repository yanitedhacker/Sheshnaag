import pytest

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
    provenance = service.get_provenance(tenant, run_id=run["id"])
    ledger = service.get_ledger(tenant)
    disclosures = service.create_disclosure_bundle(
        tenant,
        run_id=run["id"],
        bundle_type="vendor_disclosure",
        title="Gateway validation disclosure bundle",
        signed_by="Owner Analyst",
    )

    assert assigned["assignment_state"] == "assigned"
    assert approved["revisions"][0]["approval_state"] == "approved"
    assert run["state"] in {"completed", "planned", "blocked"}
    assert evidence["count"] >= 1
    assert len(artifacts["detections"]) >= 1
    assert len(artifacts["mitigations"]) >= 1
    assert provenance["count"] >= 1
    assert ledger["count"] >= 3
    assert disclosures["count"] >= 1
