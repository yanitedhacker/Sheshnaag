import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.tenancy import get_or_create_demo_tenant
from app.models import Asset, Patch, Service, SoftwareComponent, VexStatement
from app.services.auth_service import AuthService
from app.services.copilot_service import CopilotService
from app.services.demo_seed_service import DemoSeedService
from app.services.graph_service import ExposureGraphService
from app.services.import_service import ImportService
from app.services.simulation_service import SimulationService
from app.services.workbench_service import WorkbenchService


def make_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return TestingSessionLocal()


@pytest.mark.unit
def test_demo_seed_creates_public_tenant_and_assets():
    session = make_session()
    DemoSeedService(session).seed()
    session.commit()

    tenant = get_or_create_demo_tenant(session)
    assets = session.query(Asset).filter(Asset.tenant_id == tenant.id).all()
    patches = session.query(Patch).all()

    assert tenant.slug == "demo-public"
    assert len(assets) >= 3
    assert len(patches) >= 3


@pytest.mark.unit
def test_workbench_summary_returns_ranked_actions_with_signals():
    session = make_session()
    DemoSeedService(session).seed()
    session.commit()

    tenant = get_or_create_demo_tenant(session)
    summary = WorkbenchService(session).get_summary(tenant, limit=10)

    assert summary["count"] >= 1
    top = summary["actions"][0]
    assert top["action_id"].startswith("patch:")
    assert "signals" in top
    assert "evidence" in top


@pytest.mark.unit
def test_attack_graph_returns_paths_for_demo_tenant():
    session = make_session()
    DemoSeedService(session).seed()
    session.commit()

    tenant = get_or_create_demo_tenant(session)
    graph = ExposureGraphService(session).get_attack_paths(tenant, limit=5)

    assert len(graph["nodes"]) >= 1
    assert len(graph["edges"]) >= 1
    assert len(graph["paths"]) >= 1


@pytest.mark.unit
def test_simulation_and_copilot_use_seeded_demo_data():
    session = make_session()
    DemoSeedService(session).seed()
    session.commit()

    tenant = get_or_create_demo_tenant(session)
    simulation = SimulationService(session).run_risk_simulation(
        tenant,
        parameters={
            "delay_days": 14,
            "downtime_budget_minutes": 30,
            "team_capacity": 2,
            "public_exposure_weight": 1.2,
            "crown_jewel_weight": 1.1,
            "compensating_controls": True,
        },
        persist=False,
    )
    copilot = CopilotService(session).answer(tenant, "Why is the top action ranked first?")

    assert simulation["summary"]["actions_selected"] >= 1
    assert len(simulation["after"]["actions"]) >= 1
    assert copilot["cannot_answer_reason"] is None
    assert "Why" in copilot["answer_markdown"] or "ranked first" in copilot["answer_markdown"]


@pytest.mark.unit
def test_private_tenant_onboarding_and_login_work():
    session = make_session()

    service = AuthService(session)
    onboard = service.onboard_private_tenant(
        tenant_name="Acme Private",
        tenant_slug="acme-private",
        admin_email="owner@example.com",
        admin_password="supersecure123",
        admin_name="Owner Example",
    )
    session.commit()

    login = service.login(email="owner@example.com", password="supersecure123", tenant_slug="acme-private")

    assert onboard["tenant"]["slug"] == "acme-private"
    assert onboard["memberships"][0]["role"] == "owner"
    assert login["memberships"][0]["tenant_slug"] == "acme-private"
    assert login["token"]["token_type"] == "bearer"


@pytest.mark.unit
def test_import_service_handles_cyclonedx_and_openvex_shapes():
    session = make_session()
    auth = AuthService(session)
    onboard = auth.onboard_private_tenant(
        tenant_name="Supply Chain Tenant",
        tenant_slug="supply-chain",
        admin_email="supply@example.com",
        admin_password="supersecure123",
    )
    tenant_id = onboard["tenant"]["id"]

    asset = Asset(
        tenant_id=tenant_id,
        name="checkout-private-01",
        asset_type="application",
        environment="production",
        criticality="high",
        business_criticality="high",
        installed_software=[],
    )
    session.add(asset)
    session.flush()

    importer = ImportService(session)
    sbom = {
        "metadata": {"component": {"bom-ref": "svc-checkout", "name": "checkout-service", "type": "service"}},
        "services": [
            {"bom-ref": "svc-checkout", "name": "checkout-service", "type": "service"},
            {"bom-ref": "svc-payments", "name": "payments-api", "type": "service"},
        ],
        "components": [
            {
                "bom-ref": "cmp-payments",
                "publisher": "acme",
                "name": "payments-api",
                "version": "2.3.0",
                "type": "application",
                "description": "Private workspace payments component.",
            }
        ],
        "dependencies": [{"ref": "svc-checkout", "dependsOn": ["svc-payments"]}],
    }
    sbom_result = importer.import_sbom(auth.resolve_private_tenant(token_data=None, tenant_id=tenant_id), document=sbom, asset_id=asset.id)
    session.flush()

    openvex = {
        "@id": "https://example.com/openvex/private",
        "statements": [
            {
                "vulnerability": {"name": "CVE-2024-10002"},
                "products": [{"@id": "cmp-payments", "name": "payments-api", "version": "2.3.0"}],
                "status": "under_investigation",
                "justification": "Validating exploitability in the private workspace.",
            }
        ],
    }
    vex_result = importer.import_vex(auth.resolve_private_tenant(token_data=None, tenant_id=tenant_id), document=openvex)
    session.commit()

    assert sbom_result["components_created"] >= 1
    assert sbom_result["services_created"] >= 2
    assert session.query(Service).filter(Service.tenant_id == tenant_id).count() >= 2
    assert session.query(SoftwareComponent).filter(SoftwareComponent.tenant_id == tenant_id).count() >= 1
    assert vex_result["statements_created"] >= 1
    assert session.query(VexStatement).filter(VexStatement.tenant_id == tenant_id).count() >= 1


@pytest.mark.unit
def test_governance_feedback_and_approvals_shape_workbench_actions():
    session = make_session()
    DemoSeedService(session).seed()
    session.commit()

    tenant = get_or_create_demo_tenant(session)
    summary = WorkbenchService(session).get_summary(tenant, limit=10)
    top = summary["actions"][0]

    assert top["approval_state"] in {"approved", "pending", "pending_review"}
    assert top["signals"]["vex_status"] in {"unknown", "resolved", "affected", "under_investigation"}
    assert any(item["kind"] in {"analyst", "governance"} for item in top["evidence"])
