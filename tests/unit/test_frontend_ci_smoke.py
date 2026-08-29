"""Tests for the CI route and permission-gate smoke contract."""

from pathlib import Path

from scripts import sheshnaag_frontend_ci_smoke as smoke


ROOT = Path(__file__).resolve().parents[2]


def test_current_frontend_has_one_to_one_gated_routes_permissions_and_nav():
    result = smoke.validate_frontend(ROOT)

    assert result["route_count"] == 28
    assert result["permission_count"] == 28
    assert result["nav_count"] == 28
    assert result["index_permission_key"] == "intel"


def test_plain_ungated_route_is_not_accepted():
    source = '<Route path="intel" element={<IntelDashboardPage />} />'

    assert smoke._parse_gated_routes(source) == {}
