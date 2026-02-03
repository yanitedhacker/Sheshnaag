import pytest


@pytest.mark.integration
def test_seed_created_patches_and_mappings(wait_for_lab_api, lab_httpx_client):
    r = lab_httpx_client.get("/api/patches/decisions", params={"delay_days": 0})
    assert r.status_code == 200
    data = r.json()
    assert data["count"] >= 1

    # At least one patch should have linked CVEs OR asset mappings from seed.
    found = False
    for d in data["decisions"]:
        pid = d["patch_id"]
        detail = lab_httpx_client.get(f"/api/patches/{pid}")
        assert detail.status_code == 200
        body = detail.json()
        if body.get("linked_cves") or body.get("asset_mappings"):
            found = True
            break

    assert found

