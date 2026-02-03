import pytest


@pytest.mark.integration
def test_patches_priorities_shape(wait_for_lab_api, lab_httpx_client):
    r = lab_httpx_client.get("/api/patches/priorities", params={"limit": 5, "delay_days": 0})
    assert r.status_code == 200
    data = r.json()
    assert data["count"] >= 1
    assert data["delay_days"] == 0
    first = data["priorities"][0]
    for key in [
        "patch_id",
        "priority_score",
        "decision",
        "expected_risk_reduction",
        "justification",
        "estimated_downtime_minutes",
        "requires_reboot",
    ]:
        assert key in first


@pytest.mark.integration
def test_patches_delay_days_changes_scores(wait_for_lab_api, lab_httpx_client):
    r0 = lab_httpx_client.get("/api/patches/priorities", params={"limit": 10, "delay_days": 0})
    r30 = lab_httpx_client.get("/api/patches/priorities", params={"limit": 10, "delay_days": 30})
    assert r0.status_code == 200 and r30.status_code == 200

    now = {p["patch_id"]: p for p in r0.json()["priorities"]}
    later = {p["patch_id"]: p for p in r30.json()["priorities"]}
    common = set(now.keys()) & set(later.keys())
    assert common  # should have overlap

    # At least one patch should change score due to time pressure multiplier shift.
    changed = any(abs(now[pid]["priority_score"] - later[pid]["priority_score"]) > 1e-9 for pid in common)
    assert changed


@pytest.mark.integration
def test_patch_detail_links(wait_for_lab_api, lab_httpx_client):
    r = lab_httpx_client.get("/api/patches/priorities", params={"limit": 1, "delay_days": 0})
    patch_id = r.json()["priorities"][0]["patch_id"]

    detail = lab_httpx_client.get(f"/api/patches/{patch_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["patch"]["patch_id"] == patch_id
    assert "linked_cves" in body
    assert "asset_mappings" in body


@pytest.mark.integration
def test_patch_schedule_endpoint(wait_for_lab_api, lab_httpx_client):
    r = lab_httpx_client.post("/api/patches/schedule", json={"downtime_budget_minutes": 30, "team_capacity": 2})
    assert r.status_code == 200
    data = r.json()
    assert "schedule" in data

