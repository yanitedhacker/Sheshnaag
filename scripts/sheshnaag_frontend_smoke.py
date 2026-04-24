#!/usr/bin/env python3
"""Static route smoke check for Sheshnaag operator pages."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_TSX = ROOT / "frontend" / "src" / "App.tsx"
LAYOUT_TSX = ROOT / "frontend" / "src" / "components" / "Layout.tsx"

EXPECTED_ROUTES = {
    "/": "IntelDashboardPage",
    "intel": "IntelDashboardPage",
    "review": "ReviewQueuePage",
    "candidates": "CandidateQueuePage",
    "recipes": "RecipeBuilderPage",
    "runs": "RunConsolePage",
    "authorization": "AuthorizationCenterPage",
    "attack-coverage": "AttackCoveragePage",
    "evidence": "EvidenceExplorerPage",
    "artifacts": "ArtifactForgePage",
    "provenance": "ProvenanceCenterPage",
    "ledger": "AnalystLedgerPage",
    "disclosures": "DisclosureBundlesPage",
}

EXPECTED_PAGE_FILES = {
    "IntelDashboardPage": ROOT / "frontend" / "src" / "pages" / "IntelDashboardPage.tsx",
    "ReviewQueuePage": ROOT / "frontend" / "src" / "pages" / "ReviewQueuePage.tsx",
    "CandidateQueuePage": ROOT / "frontend" / "src" / "pages" / "CandidateQueuePage.tsx",
    "RecipeBuilderPage": ROOT / "frontend" / "src" / "pages" / "RecipeBuilderPage.tsx",
    "RunConsolePage": ROOT / "frontend" / "src" / "pages" / "RunConsolePage.tsx",
    "AuthorizationCenterPage": ROOT / "frontend" / "src" / "pages" / "AuthorizationCenterPage.tsx",
    "AttackCoveragePage": ROOT / "frontend" / "src" / "pages" / "AttackCoveragePage.tsx",
    "EvidenceExplorerPage": ROOT / "frontend" / "src" / "pages" / "EvidenceExplorerPage.tsx",
    "ArtifactForgePage": ROOT / "frontend" / "src" / "pages" / "ArtifactForgePage.tsx",
    "ProvenanceCenterPage": ROOT / "frontend" / "src" / "pages" / "ProvenanceCenterPage.tsx",
    "AnalystLedgerPage": ROOT / "frontend" / "src" / "pages" / "AnalystLedgerPage.tsx",
    "DisclosureBundlesPage": ROOT / "frontend" / "src" / "pages" / "DisclosureBundlesPage.tsx",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    app_text = APP_TSX.read_text()
    layout_text = LAYOUT_TSX.read_text()
    report: list[str] = []

    for route, component in EXPECTED_ROUTES.items():
        if route == "/":
            needle = f"<Route index element={{<{component} />}} />"
        else:
            needle = f'<Route path="{route}" element={{<{component} />}} />'
        require(needle in app_text, f"missing route declaration for {route} -> {component}")
        report.append(f"route {route} -> {component}")

    for component, path in EXPECTED_PAGE_FILES.items():
        require(path.exists(), f"missing page file for {component}: {path}")
        require(component in app_text, f"missing import or usage for {component} in App.tsx")
        report.append(f"page file present for {component}")

    for nav_path in [
        "/intel",
        "/review",
        "/candidates",
        "/recipes",
        "/runs",
        "/authorization",
        "/attack-coverage",
        "/evidence",
        "/artifacts",
        "/provenance",
        "/ledger",
        "/disclosures",
    ]:
        require(f'{{ to: "{nav_path}"' in layout_text, f"missing nav config entry for {nav_path}")
        report.append(f"nav link present for {nav_path}")

    print("Sheshnaag frontend route smoke summary")
    for line in report:
        print(f"- {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
