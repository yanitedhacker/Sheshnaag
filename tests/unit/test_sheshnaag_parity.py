from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.tenancy import get_or_create_demo_tenant
from app.lab.attestation import Ed25519AttestationSigner
from app.models import Asset
from app.models.sheshnaag import KnowledgeWikiPage, RawKnowledgeSource
from app.models.v2 import KnowledgeDocument
from app.services.auth_service import AuthService
from app.services.demo_seed_service import DemoSeedService
from app.services.knowledge_service import KnowledgeRetrievalService
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


def _private_tenant_with_asset(session):
    DemoSeedService(session).seed()
    auth = AuthService(session)
    onboard = auth.onboard_private_tenant(
        tenant_name="Parity Tenant",
        tenant_slug="parity-private",
        admin_email="owner@sheshnaag.local",
        admin_password="supersecure123",
        admin_name="Parity Owner",
    )
    tenant = auth.resolve_private_tenant(token_data=None, tenant_id=onboard["tenant"]["id"])
    session.add(
        Asset(
            tenant_id=tenant.id,
            name="gateway",
            asset_type="application",
            environment="production",
            criticality="high",
            business_criticality="high",
            installed_software=[{"vendor": "acme", "product": "acme-api-gateway", "version": "7.4.2"}],
        )
    )
    session.commit()
    return tenant


def test_live_alias_normalizes_to_execute_and_bundle_urls_are_tenant_aware():
    session = make_session()
    tenant = _private_tenant_with_asset(session)
    service = SheshnaagService(session)

    candidate = service.list_candidates(tenant, limit=1)["items"][0]
    recipe = service.create_recipe(
        tenant,
        candidate_id=candidate["id"],
        name="Parity recipe",
        objective="Validate canonical launch-mode semantics.",
        created_by="Parity Owner",
        content={"command": ["bash", "-lc", "echo parity"], "network_policy": {"allow_egress_hosts": []}},
    )
    service.approve_recipe_revision(tenant, recipe_id=recipe["id"], revision_number=1, reviewer="Lead Reviewer")

    run = service.launch_run(
        tenant,
        recipe_id=recipe["id"],
        revision_number=1,
        analyst_name="Parity Owner",
        workstation={"hostname": "mbp", "os_family": "macOS", "architecture": "arm64", "fingerprint": "parity-fp"},
        launch_mode="live",
        acknowledge_sensitive=False,
    )
    bundle = service.create_disclosure_bundle(
        tenant,
        run_id=run["id"],
        bundle_type="vendor_disclosure",
        title="Parity bundle",
        signed_by="Parity Owner",
        confirm_external_export=True,
    )

    assert run["launch_mode"] == "execute"
    assert run["state"] == "queued"
    assert any(event["event_type"] == "run_queued" for event in run["timeline"])
    assert run["provider_readiness"]["status"] in {"ready", "degraded", "unavailable"}
    assert len(run["collector_capabilities"]) >= 5
    assert "tenant_slug=parity-private" in bundle["download_url"]
    assert bundle["signing"]["algorithm"] == "ed25519"


def test_knowledge_backfill_creates_raw_sources_and_wiki_pages():
    session = make_session()
    tenant = get_or_create_demo_tenant(session)
    knowledge = KnowledgeRetrievalService(session)
    session.add(
        KnowledgeDocument(
            tenant_id=tenant.id,
            document_type="advisory",
            title="Vendor advisory",
            content="Original advisory body",
            source_label="Vendor Advisory",
            source_url="https://example.com/advisory",
        )
    )
    session.add(
        KnowledgeDocument(
            tenant_id=tenant.id,
            document_type="attack-note",
            title="Operator note",
            content="Summarized operator wiki note",
            source_label="Operator Note",
            source_url=None,
        )
    )
    session.commit()

    knowledge.backfill_knowledge_layers()

    assert session.query(RawKnowledgeSource).count() == 1
    assert session.query(KnowledgeWikiPage).count() == 1
    retrieval_docs = session.query(KnowledgeDocument).all()
    assert any(doc.document_type == "raw-source" for doc in retrieval_docs)
    assert any(doc.document_type == "wiki" for doc in retrieval_docs)


def test_ed25519_signer_round_trip_verifies():
    session = make_session()
    tenant = _private_tenant_with_asset(session)
    service = SheshnaagService(session)
    key = service._ensure_tenant_signing_key(tenant)
    signer = Ed25519AttestationSigner(
        private_key_path=key.key_path or "",
        public_key=key.public_key,
        fingerprint=key.fingerprint,
    )

    signed = signer.sign(payload={"hello": "world"}, signer="Parity Owner")

    assert signed["algorithm"] == "ed25519"
    assert signer.verify(payload={"hello": "world"}, signature=signed["signature"])
