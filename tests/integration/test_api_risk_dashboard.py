import pytest


@pytest.mark.integration
def test_dashboard_endpoint(wait_for_lab_api, lab_httpx_client):
    r = lab_httpx_client.get("/api/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert "risk_summary" in data
    assert "top_priorities" in data


@pytest.mark.integration
def test_risk_summary_endpoint(wait_for_lab_api, lab_httpx_client):
    r = lab_httpx_client.get("/api/risk/summary")
    assert r.status_code == 200
    data = r.json()
    assert "risk_level_distribution" in data


@pytest.mark.integration
def test_cve_search_endpoint(wait_for_lab_api, lab_httpx_client):
    r = lab_httpx_client.get("/api/cves/", params={"page_size": 5, "keyword": "remote"})
    assert r.status_code == 200
    data = r.json()
    assert "results" in data
    assert data["page_size"] == 5

