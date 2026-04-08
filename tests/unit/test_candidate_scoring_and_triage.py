"""WS2 unit tests for candidate scoring, status transitions, actions, and filters."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.tenancy import get_or_create_demo_tenant
from app.models.asset import Asset
from app.models.cve import CVE
from app.models.sheshnaag import ResearchCandidate
from app.services.auth_service import AuthService
from app.services.demo_seed_service import DemoSeedService
from app.services.sheshnaag_service import (
    CANDIDATE_SCORING_WEIGHTS,
    CANDIDATE_STATUS_TRANSITIONS,
    VALID_CANDIDATE_STATUSES,
    SheshnaagService,
)


def make_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return testing_session_local()


def seed_private_tenant(session):
    DemoSeedService(session).seed()
    auth = AuthService(session)
    onboard = auth.onboard_private_tenant(
        tenant_name="Pod B Test Tenant",
        tenant_slug="pod-b-test",
        admin_email="podbtest@sheshnaag.local",
        admin_password="testpass123",
        admin_name="Pod B Tester",
    )
    tenant = auth.resolve_private_tenant(token_data=None, tenant_id=onboard["tenant"]["id"])
    session.add(
        Asset(
            tenant_id=tenant.id,
            name="test-gateway",
            asset_type="application",
            environment="production",
            criticality="high",
            business_criticality="high",
            installed_software=[{"vendor": "acme", "product": "acme-api-gateway", "version": "7.4.2"}],
        )
    )
    session.commit()
    return tenant


# ---------------------------------------------------------------------------
# WS2-T1: Scoring factor tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestScoringWeights:
    def test_weights_sum_to_one(self):
        total = sum(CANDIDATE_SCORING_WEIGHTS.values())
        assert abs(total - 1.0) < 0.001, f"Weights sum to {total}, expected 1.0"

    def test_all_weights_positive(self):
        for key, value in CANDIDATE_SCORING_WEIGHTS.items():
            assert value > 0, f"Weight '{key}' must be positive, got {value}"

    def test_expected_factor_keys_present(self):
        expected = {
            "risk_score", "epss", "kev", "package_match_confidence",
            "attack_surface", "observability", "linux_reproducibility",
            "patch_availability", "exploit_maturity",
        }
        assert set(CANDIDATE_SCORING_WEIGHTS.keys()) == expected


@pytest.mark.unit
class TestScoringFactors:
    def test_explainability_contains_factor_details(self):
        session = make_session()
        DemoSeedService(session).seed()
        session.commit()
        tenant = get_or_create_demo_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5)
        assert candidates["count"] >= 1
        item = candidates["items"][0]
        explain = item["explainability"]

        assert "factor_details" in explain
        assert "weights" in explain
        assert len(explain["factor_details"]) == len(CANDIDATE_SCORING_WEIGHTS)

        for detail in explain["factor_details"]:
            assert "key" in detail
            assert "raw" in detail
            assert "weight" in detail
            assert "weighted" in detail
            assert "reason" in detail
            assert detail["key"] in CANDIDATE_SCORING_WEIGHTS

    def test_score_is_weighted_sum(self):
        session = make_session()
        DemoSeedService(session).seed()
        session.commit()
        tenant = get_or_create_demo_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5)
        item = candidates["items"][0]
        explain = item["explainability"]

        recomputed = sum(d["weighted"] for d in explain["factor_details"]) * 100.0
        assert abs(explain["score"] - round(recomputed, 2)) < 0.1

    def test_each_factor_contributes_within_bounds(self):
        session = make_session()
        DemoSeedService(session).seed()
        session.commit()
        tenant = get_or_create_demo_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5)
        for item in candidates["items"]:
            for detail in item["explainability"]["factor_details"]:
                assert 0.0 <= detail["raw"] <= 1.0, f"Factor {detail['key']} raw={detail['raw']} out of [0,1]"

    def test_score_boundary_above_threshold_is_queued(self):
        session = make_session()
        DemoSeedService(session).seed()
        session.commit()
        tenant = get_or_create_demo_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=20)
        for item in candidates["items"]:
            if item["candidate_score"] >= 35:
                assert item["status"] in ("queued", "in_review"), f"Score {item['candidate_score']} should be queued"

    def test_score_boundary_below_threshold_is_deferred(self):
        session = make_session()
        DemoSeedService(session).seed()
        session.commit()
        tenant = get_or_create_demo_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=20)
        for item in candidates["items"]:
            if item["candidate_score"] < 35:
                assert item["status"] == "deferred", f"Score {item['candidate_score']} should be deferred"


# ---------------------------------------------------------------------------
# WS2-T2: Status transition tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestStatusTransitions:
    def test_valid_statuses(self):
        assert VALID_CANDIDATE_STATUSES == {"queued", "deferred", "in_review", "rejected", "duplicate", "archived"}

    def test_transition_queued_to_deferred(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5, status="queued")
        if candidates["count"] == 0:
            pytest.skip("No queued candidates to test")
        cid = candidates["items"][0]["id"]
        result = svc.transition_candidate_status(tenant, candidate_id=cid, new_status="deferred", reason="Postponed", changed_by="tester")
        assert result["status"] == "deferred"
        assert result["status_reason"] == "Postponed"
        assert result["status_changed_by"] == "tester"

    def test_transition_queued_to_rejected(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5, status="queued")
        if candidates["count"] == 0:
            pytest.skip("No queued candidates to test")
        cid = candidates["items"][0]["id"]
        result = svc.transition_candidate_status(tenant, candidate_id=cid, new_status="rejected", reason="Not applicable")
        assert result["status"] == "rejected"

    def test_transition_rejected_to_queued(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5, status="queued")
        if candidates["count"] == 0:
            pytest.skip("No queued candidates to test")
        cid = candidates["items"][0]["id"]
        svc.transition_candidate_status(tenant, candidate_id=cid, new_status="rejected")
        result = svc.transition_candidate_status(tenant, candidate_id=cid, new_status="queued", reason="Re-evaluating")
        assert result["status"] == "queued"

    def test_invalid_transition_raises(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5, status="queued")
        if candidates["count"] == 0:
            pytest.skip("No queued candidates to test")
        cid = candidates["items"][0]["id"]
        svc.transition_candidate_status(tenant, candidate_id=cid, new_status="rejected")
        with pytest.raises(ValueError, match="Cannot transition"):
            svc.transition_candidate_status(tenant, candidate_id=cid, new_status="in_review")

    def test_invalid_status_raises(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5)
        cid = candidates["items"][0]["id"]
        with pytest.raises(ValueError, match="Invalid status"):
            svc.transition_candidate_status(tenant, candidate_id=cid, new_status="nonexistent")

    def test_duplicate_has_no_outbound_transitions(self):
        assert CANDIDATE_STATUS_TRANSITIONS["duplicate"] == set()

    def test_archived_can_only_restore_to_queued(self):
        assert CANDIDATE_STATUS_TRANSITIONS["archived"] == {"queued"}


# ---------------------------------------------------------------------------
# WS2-T3: Candidate action tests (merge duplicate)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCandidateMerge:
    def test_merge_duplicate(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=10, status="queued")
        if candidates["count"] < 2:
            pytest.skip("Need at least 2 queued candidates")
        id_a = candidates["items"][0]["id"]
        id_b = candidates["items"][1]["id"]
        result = svc.merge_candidate_duplicate(tenant, candidate_id=id_a, merge_into_id=id_b, merged_by="tester")
        assert result["merged"]["status"] == "duplicate"
        assert result["merged"]["merged_into_id"] == id_b

    def test_merge_into_self_raises(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5, status="queued")
        if candidates["count"] == 0:
            pytest.skip("No queued candidates")
        cid = candidates["items"][0]["id"]
        with pytest.raises(ValueError, match="cannot be merged into itself"):
            svc.merge_candidate_duplicate(tenant, candidate_id=cid, merge_into_id=cid)

    def test_merge_from_rejected_raises(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5, status="queued")
        if candidates["count"] < 2:
            pytest.skip("Need at least 2 candidates")
        id_a = candidates["items"][0]["id"]
        id_b = candidates["items"][1]["id"]
        svc.transition_candidate_status(tenant, candidate_id=id_a, new_status="rejected")
        with pytest.raises(ValueError, match="Cannot mark candidate"):
            svc.merge_candidate_duplicate(tenant, candidate_id=id_a, merge_into_id=id_b)


# ---------------------------------------------------------------------------
# WS2-T4: Filter tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCandidateFilters:
    def test_filter_by_status(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        all_items = svc.list_candidates(tenant, limit=50)
        queued = svc.list_candidates(tenant, limit=50, status="queued")
        deferred = svc.list_candidates(tenant, limit=50, status="deferred")
        assert queued["total"] + deferred["total"] <= all_items["total"]

    def test_filter_by_patch_available(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        patched = svc.list_candidates(tenant, limit=50, patch_available=True)
        unpatched = svc.list_candidates(tenant, limit=50, patch_available=False)
        for item in patched["items"]:
            assert item["patch_available"] is True
        for item in unpatched["items"]:
            assert item["patch_available"] is False

    def test_filter_by_min_score(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        result = svc.list_candidates(tenant, limit=50, min_score=35.0)
        for item in result["items"]:
            assert item["candidate_score"] >= 35.0

    def test_filter_by_max_score(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        result = svc.list_candidates(tenant, limit=50, max_score=50.0)
        for item in result["items"]:
            assert item["candidate_score"] <= 50.0

    def test_filter_by_assignment_state(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5, status="queued")
        if candidates["count"] > 0:
            svc.assign_candidate(tenant, candidate_id=candidates["items"][0]["id"], analyst_name="FilterTester")
        assigned = svc.list_candidates(tenant, limit=50, assignment_state="assigned")
        for item in assigned["items"]:
            assert item["assignment_state"] == "assigned"

    def test_pagination(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        page1 = svc.list_candidates(tenant, limit=2, offset=0)
        page2 = svc.list_candidates(tenant, limit=2, offset=2)
        assert page1["offset"] == 0
        assert page1["limit"] == 2
        assert len(page1["items"]) <= 2
        if page1["total"] > 2:
            assert len(page2["items"]) > 0
            p1_ids = {i["id"] for i in page1["items"]}
            p2_ids = {i["id"] for i in page2["items"]}
            assert p1_ids.isdisjoint(p2_ids)

    def test_sort_ascending(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        result = svc.list_candidates(tenant, limit=50, sort_by="score", sort_order="asc")
        scores = [i["candidate_score"] for i in result["items"]]
        assert scores == sorted(scores)

    def test_sort_descending(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        result = svc.list_candidates(tenant, limit=50, sort_by="score", sort_order="desc")
        scores = [i["candidate_score"] for i in result["items"]]
        assert scores == sorted(scores, reverse=True)

    def test_combined_filters(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        result = svc.list_candidates(tenant, limit=50, status="queued", min_score=10.0, sort_by="score", sort_order="desc")
        for item in result["items"]:
            assert item["status"] == "queued"
            assert item["candidate_score"] >= 10.0

    def test_filter_by_exploit_available(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        first = svc.list_candidates(tenant, limit=1)
        if first["count"] < 1:
            pytest.skip("No candidates")
        cid = first["items"][0]["id"]
        rc = session.query(ResearchCandidate).filter(ResearchCandidate.id == cid).first()
        cve_row = session.query(CVE).filter(CVE.id == rc.cve_id).first()
        cve_row.exploit_available = True
        session.commit()
        r_true = svc.list_candidates(tenant, limit=50, exploit_available=True)
        assert any(i["id"] == cid for i in r_true["items"])
        r_false = svc.list_candidates(tenant, limit=50, exploit_available=False)
        assert all(i["id"] != cid for i in r_false["items"])

    def test_filter_by_observability_bounds(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        first = svc.list_candidates(tenant, limit=1)
        if first["count"] < 1:
            pytest.skip("No candidates")
        cid = first["items"][0]["id"]
        rc = session.query(ResearchCandidate).filter(ResearchCandidate.id == cid).first()
        rc.observability_score = 0.85
        session.commit()
        hi = svc.list_candidates(tenant, limit=50, min_observability=0.8)
        assert any(i["id"] == cid for i in hi["items"])
        lo = svc.list_candidates(tenant, limit=50, max_observability=0.1)
        assert all(i["id"] != cid for i in lo["items"])


# ---------------------------------------------------------------------------
# WS2-T5: Environment applicability tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestEnvironmentApplicability:
    def test_explainability_contains_applicability(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5)
        for item in candidates["items"]:
            assert "environment_applicability" in item["explainability"]
            app = item["explainability"]["environment_applicability"]
            assert "match_sources" in app
            assert "confidence" in app
            assert isinstance(app["confidence"], float)


# ---------------------------------------------------------------------------
# WS2-T6: Citation tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCandidateCitations:
    def test_citations_present_and_normalized(self):
        session = make_session()
        DemoSeedService(session).seed()
        session.commit()
        tenant = get_or_create_demo_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5)
        for item in candidates["items"]:
            citations = item["explainability"]["citations"]
            assert isinstance(citations, list)
            for citation in citations:
                assert "type" in citation
                assert "label" in citation

    def test_kev_candidate_has_kev_citation(self):
        session = make_session()
        DemoSeedService(session).seed()
        session.commit()
        tenant = get_or_create_demo_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=20)
        kev_candidates = [
            c for c in candidates["items"]
            if c["explainability"]["factors"].get("kev") is True
        ]
        for c in kev_candidates:
            types = [cit["type"] for cit in c["explainability"]["citations"]]
            assert "kev" in types


# ---------------------------------------------------------------------------
# WS2-T7: Assignment metadata and workload tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAssignmentMetadata:
    def test_assign_sets_metadata(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5, status="queued")
        if candidates["count"] == 0:
            pytest.skip("No queued candidates")
        cid = candidates["items"][0]["id"]
        result = svc.assign_candidate(tenant, candidate_id=cid, analyst_name="Alice", assigned_by="Bob")
        assert result["assigned_to"] == "Alice"
        assert result["assigned_by"] == "Bob"
        assert result["assigned_at"] is not None
        assert result["assignment_state"] == "assigned"

    def test_workload_summary(self):
        session = make_session()
        tenant = seed_private_tenant(session)
        svc = SheshnaagService(session)
        candidates = svc.list_candidates(tenant, limit=5, status="queued")
        if candidates["count"] >= 2:
            svc.assign_candidate(tenant, candidate_id=candidates["items"][0]["id"], analyst_name="Alice")
            svc.assign_candidate(tenant, candidate_id=candidates["items"][1]["id"], analyst_name="Alice")
        summary = svc.get_workload_summary(tenant)
        assert "total_active" in summary
        assert "unassigned" in summary
        assert "by_analyst" in summary
        assert "by_status" in summary
        if candidates["count"] >= 2:
            alice_entry = next((a for a in summary["by_analyst"] if a["analyst"] == "Alice"), None)
            assert alice_entry is not None
            assert alice_entry["count"] >= 2
