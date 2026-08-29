#!/usr/bin/env python3
"""Verify the committed frontend route, permission, and navigation contract."""

from __future__ import annotations

import re
from pathlib import Path


REQUIRED_ROUTE_KEYS = frozenset(
    {
        "intel",
        "review",
        "candidates",
        "recipes",
        "runs",
        "authorization",
        "attack-coverage",
        "case-graph",
        "autonomous",
        "evidence",
        "artifacts",
        "provenance",
        "ledger",
        "disclosures",
        "specimens",
        "analysis-cases",
        "sandbox-profiles",
        "findings",
        "indicators",
        "prevention-v3",
        "defang",
        "reports",
        "ai-sessions",
        "policy",
        "workers",
        "analytics",
    }
)

_GATED_ROUTE_RE = re.compile(
    r'<Route\s+path="([^"]+)"\s+element=\{gated\("([^"]+)",\s*<([A-Za-z0-9_]+)\s*/>\)\}\s*/>'
)
_INDEX_RE = re.compile(
    r'<Route\s+index\s+element=\{gated\("([^"]+)",\s*<([A-Za-z0-9_]+)\s*/>\)\}\s*/>'
)
_NAV_RE = re.compile(
    r'\{\s*to:\s*"/([^"]+)",\s*label:\s*"[^"]+",\s*permissionKey:\s*"([^"]+)"\s*\}'
)
_PERMISSION_RE = re.compile(
    r'^\s*(?:"([^"]+)"|([A-Za-z][A-Za-z0-9_]*)):\s*"([^"]+)"',
    re.MULTILINE,
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _parse_gated_routes(source: str) -> dict[str, tuple[str, str]]:
    return {
        path: (permission_key, component)
        for path, permission_key, component in _GATED_ROUTE_RE.findall(source)
        if path != "*"
    }


def _route_permission_block(source: str) -> str:
    marker = "export const ROUTE_PERMISSIONS"
    start = source.find(marker)
    _require(start >= 0, "missing ROUTE_PERMISSIONS declaration")
    opening = source.find("{", start)
    closing = source.find("};", opening)
    _require(opening >= 0 and closing > opening, "invalid ROUTE_PERMISSIONS block")
    return source[opening + 1 : closing]


def _parse_route_permissions(source: str) -> dict[str, str]:
    rows: dict[str, str] = {}
    for quoted, bare, permission in _PERMISSION_RE.findall(
        _route_permission_block(source)
    ):
        rows[quoted or bare] = permission
    return rows


def _parse_navigation(source: str) -> dict[str, str]:
    return {path: permission_key for path, permission_key in _NAV_RE.findall(source)}


def validate_frontend(root: Path) -> dict[str, object]:
    frontend = root / "frontend" / "src"
    app_source = (frontend / "App.tsx").read_text(encoding="utf-8")
    layout_source = (frontend / "components" / "Layout.tsx").read_text(
        encoding="utf-8"
    )
    permissions_source = (frontend / "permissions.ts").read_text(encoding="utf-8")
    role_gate_source = (frontend / "components" / "RoleGate.tsx").read_text(
        encoding="utf-8"
    )

    routes = _parse_gated_routes(app_source)
    permissions = _parse_route_permissions(permissions_source)
    navigation = _parse_navigation(layout_source)
    index_matches = _INDEX_RE.findall(app_source)
    wildcard_matches = [
        (permission_key, component)
        for path, permission_key, component in _GATED_ROUTE_RE.findall(app_source)
        if path == "*"
    ]

    _require(len(index_matches) == 1, "index route must have one permission gate")
    index_permission_key, index_component = index_matches[0]
    _require(
        index_permission_key == "intel" and index_component == "IntelDashboardPage",
        "index route must use the intel permission gate",
    )
    _require(
        wildcard_matches == [("intel", "IntelDashboardPage")],
        "wildcard route must use the intel permission gate",
    )
    _require(
        REQUIRED_ROUTE_KEYS.issubset(routes),
        f"missing gated routes: {sorted(REQUIRED_ROUTE_KEYS - routes.keys())}",
    )
    _require(
        all(path == permission_key for path, (permission_key, _component) in routes.items()),
        "each route path must use its matching ROUTE_PERMISSIONS key",
    )
    _require(
        set(routes) == set(permissions),
        "gated route keys and ROUTE_PERMISSIONS keys must match exactly",
    )
    _require(
        set(routes) == set(navigation),
        "gated route keys and navigation keys must match exactly",
    )
    _require(
        all(path == permission_key for path, permission_key in navigation.items()),
        "each navigation item must use its matching permission key",
    )
    _require(
        'fallback={<NotAuthorizedPage />}' in app_source,
        "route gates must render NotAuthorizedPage when access is denied",
    )
    _require(
        "if (!hasPermission(permission))" in role_gate_source,
        "RoleGate must deny a missing permission",
    )
    _require(
        "RoleAwareNavLink" in layout_source
        and "isAuthenticated && !hasPermission(permission)" in layout_source,
        "navigation must hide denied links for authenticated users",
    )
    _require(
        permissions.get("workers") == "admin.roles.assign",
        "worker fleet must require admin.roles.assign",
    )
    _require(
        permissions.get("analytics") == "analytics.read",
        "team analytics must require analytics.read",
    )
    _require(
        "RESERVED_FOR_V7" in permissions_source,
        "missing RESERVED_FOR_V7 capability block",
    )

    page_root = frontend / "pages"
    for _path, (_permission_key, component) in routes.items():
        _require(
            (page_root / f"{component}.tsx").is_file(),
            f"missing page component file: {component}.tsx",
        )

    return {
        "route_count": len(routes),
        "permission_count": len(permissions),
        "nav_count": len(navigation),
        "index_permission_key": index_permission_key,
        "route_keys": sorted(routes),
    }


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    result = validate_frontend(root)
    print("Sheshnaag frontend route/permission CI smoke")
    print(f"- gated routes: {result['route_count']}")
    print(f"- permission entries: {result['permission_count']}")
    print(f"- role-aware nav items: {result['nav_count']}")
    print(f"- index permission key: {result['index_permission_key']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
