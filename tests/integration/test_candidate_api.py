"""WS2-T8 integration tests for candidate APIs.

These require the lab API to be running. Set RUN_INTEGRATION_TESTS=1
and ensure the API is available at LAB_API_BASE (default http://localhost:8000).
"""

import pytest

pytestmark = pytest.mark.integration


class TestCandidateListAPI:
    def test_list_candidates_returns_200(self, wait_for_lab_api, lab_httpx_client):
        r = lab_httpx_client.get("/api/candidates")
        assert r.status_code == 200
        data = r.json()
        assert "items" in data
        assert "total" in data or "count" in data

    def test_list_with_status_filter(self, wait_for_lab_api, lab_httpx_client):
        r = lab_httpx_client.get("/api/candidates", params={"status": "queued"})
        assert r.status_code == 200
        for item in r.json()["items"]:
            assert item["status"] == "queued"

    def test_list_with_patch_filter(self, wait_for_lab_api, lab_httpx_client):
        r = lab_httpx_client.get("/api/candidates", params={"patch_available": "true"})
        assert r.status_code == 200

    def test_list_with_score_range(self, wait_for_lab_api, lab_httpx_client):
        r = lab_httpx_client.get("/api/candidates", params={"min_score": 10, "max_score": 90})
        assert r.status_code == 200
        for item in r.json()["items"]:
            assert 10 <= item["candidate_score"] <= 90

    def test_list_with_pagination(self, wait_for_lab_api, lab_httpx_client):
        r1 = lab_httpx_client.get("/api/candidates", params={"limit": 2, "offset": 0})
        r2 = lab_httpx_client.get("/api/candidates", params={"limit": 2, "offset": 2})
        assert r1.status_code == 200
        assert r2.status_code == 200

    def test_list_with_sort(self, wait_for_lab_api, lab_httpx_client):
        r = lab_httpx_client.get("/api/candidates", params={"sort_by": "score", "sort_order": "asc"})
        assert r.status_code == 200
        scores = [i["candidate_score"] for i in r.json()["items"]]
        assert scores == sorted(scores)


class TestCandidateAssignAPI:
    def test_assign_candidate(self, wait_for_lab_api, lab_httpx_client):
        r = lab_httpx_client.get("/api/candidates", params={"status": "queued", "limit": 1})
        items = r.json().get("items", [])
        if not items:
            pytest.skip("No queued candidates")
        cid = items[0]["id"]
        r2 = lab_httpx_client.post(
            f"/api/candidates/{cid}/assign",
            json={"tenant_slug": "demo", "analyst_name": "IntegrationTester"},
        )
        assert r2.status_code == 200
        assert r2.json()["assigned_to"] == "IntegrationTester"


class TestCandidateActionsAPI:
    def _get_first_queued_id(self, client):
        r = client.get("/api/candidates", params={"status": "queued", "limit": 1})
        items = r.json().get("items", [])
        return items[0]["id"] if items else None

    def test_defer_candidate(self, wait_for_lab_api, lab_httpx_client):
        cid = self._get_first_queued_id(lab_httpx_client)
        if cid is None:
            pytest.skip("No queued candidates")
        r = lab_httpx_client.post(
            f"/api/candidates/{cid}/defer",
            json={"tenant_slug": "demo", "reason": "Integration test deferral"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "deferred"

    def test_reject_candidate(self, wait_for_lab_api, lab_httpx_client):
        cid = self._get_first_queued_id(lab_httpx_client)
        if cid is None:
            pytest.skip("No queued candidates")
        r = lab_httpx_client.post(
            f"/api/candidates/{cid}/reject",
            json={"tenant_slug": "demo", "reason": "Not relevant"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "rejected"

    def test_restore_rejected_candidate(self, wait_for_lab_api, lab_httpx_client):
        cid = self._get_first_queued_id(lab_httpx_client)
        if cid is None:
            pytest.skip("No queued candidates")
        lab_httpx_client.post(f"/api/candidates/{cid}/reject", json={"tenant_slug": "demo"})
        r = lab_httpx_client.post(
            f"/api/candidates/{cid}/restore",
            json={"tenant_slug": "demo", "reason": "Re-evaluating"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "queued"

    def test_archive_candidate(self, wait_for_lab_api, lab_httpx_client):
        cid = self._get_first_queued_id(lab_httpx_client)
        if cid is None:
            pytest.skip("No queued candidates")
        r = lab_httpx_client.post(
            f"/api/candidates/{cid}/archive",
            json={"tenant_slug": "demo"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "archived"

    def test_invalid_transition_returns_400(self, wait_for_lab_api, lab_httpx_client):
        cid = self._get_first_queued_id(lab_httpx_client)
        if cid is None:
            pytest.skip("No queued candidates")
        lab_httpx_client.post(f"/api/candidates/{cid}/reject", json={"tenant_slug": "demo"})
        r = lab_httpx_client.post(
            f"/api/candidates/{cid}/defer",
            json={"tenant_slug": "demo"},
        )
        assert r.status_code == 400


class TestCandidateMergeAPI:
    def test_merge_duplicate(self, wait_for_lab_api, lab_httpx_client):
        r = lab_httpx_client.get("/api/candidates", params={"status": "queued", "limit": 2})
        items = r.json().get("items", [])
        if len(items) < 2:
            pytest.skip("Need at least 2 queued candidates")
        r2 = lab_httpx_client.post(
            f"/api/candidates/{items[0]['id']}/merge",
            json={"tenant_slug": "demo", "merge_into_id": items[1]["id"]},
        )
        assert r2.status_code == 200
        assert r2.json()["merged"]["status"] == "duplicate"

    def test_merge_into_self_returns_400(self, wait_for_lab_api, lab_httpx_client):
        r = lab_httpx_client.get("/api/candidates", params={"status": "queued", "limit": 1})
        items = r.json().get("items", [])
        if not items:
            pytest.skip("No queued candidates")
        cid = items[0]["id"]
        r2 = lab_httpx_client.post(
            f"/api/candidates/{cid}/merge",
            json={"tenant_slug": "demo", "merge_into_id": cid},
        )
        assert r2.status_code == 400


class TestWorkloadAPI:
    def test_workload_summary(self, wait_for_lab_api, lab_httpx_client):
        r = lab_httpx_client.get("/api/candidates/workload/summary")
        assert r.status_code == 200
        data = r.json()
        assert "total_active" in data
        assert "unassigned" in data
        assert "by_analyst" in data
        assert "by_status" in data
