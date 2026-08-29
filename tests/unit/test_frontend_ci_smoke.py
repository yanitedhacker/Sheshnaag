"""Tests for the CI route, permission, and portable lock-file contracts."""

import json
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


def test_frontend_lock_contains_linux_x64_and_arm64_rolldown_bindings():
    lock = json.loads((ROOT / "frontend" / "package-lock.json").read_text())
    packages = lock["packages"]

    expected_rolldown = {
        "node_modules/@rolldown/binding-linux-arm64-gnu",
        "node_modules/@rolldown/binding-linux-arm64-musl",
        "node_modules/@rolldown/binding-linux-x64-gnu",
        "node_modules/@rolldown/binding-linux-x64-musl",
    }
    expected_lightningcss = {
        "node_modules/lightningcss-linux-arm64-gnu",
        "node_modules/lightningcss-linux-arm64-musl",
        "node_modules/lightningcss-linux-x64-gnu",
        "node_modules/lightningcss-linux-x64-musl",
    }
    assert expected_rolldown.issubset(packages)
    assert expected_lightningcss.issubset(packages)
