#!/usr/bin/env python3
"""Static route smoke check for Sheshnaag operator pages."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_TSX = ROOT / "frontend" / "src" / "App.tsx"
LAYOUT_TSX = ROOT / "frontend" / "src" / "components" / "Layout.tsx"

EXPECTED_ROUTES = {
    "/": ("intel", "IntelDashboardPage"),
    "intel": ("intel", "IntelDashboardPage"),
    "review": ("review", "ReviewQueuePage"),
    "candidates": ("candidates", "CandidateQueuePage"),
    "recipes": ("recipes", "RecipeBuilderPage"),
    "runs": ("runs", "RunConsolePage"),
    "authorization": ("authorization", "AuthorizationCenterPage"),
    "attack-coverage": ("attack-coverage", "AttackCoveragePage"),
    "case-graph": ("case-graph", "CaseGraphPage"),
    "autonomous": ("autonomous", "AutonomousAgentPage"),
    "evidence": ("evidence", "EvidenceExplorerPage"),
    "artifacts": ("artifacts", "ArtifactForgePage"),
    "provenance": ("provenance", "ProvenanceCenterPage"),
    "ledger": ("ledger", "AnalystLedgerPage"),
    "disclosures": ("disclosures", "DisclosureBundlesPage"),
    "specimens": ("specimens", "SpecimenIntakePage"),
    "analysis-cases": ("analysis-cases", "AnalysisCasesPage"),
    "sandbox-profiles": ("sandbox-profiles", "SandboxProfilesPage"),
    "findings": ("findings", "BehaviorFindingsPage"),
    "indicators": ("indicators", "IndicatorForgeV3Page"),
    "prevention-v3": ("prevention-v3", "PreventionForgeV3Page"),
    "defang": ("defang", "DefangQueuePage"),
    "reports": ("reports", "MalwareReportsPage"),
    "ai-sessions": ("ai-sessions", "AISessionsPage"),
    "policy": ("policy", "PolicyCenterPage"),
    "workers": ("workers", "WorkerFleetPage"),
    "analytics": ("analytics", "TeamAnalyticsPage"),
    "purple-team": ("purple-team", "PurpleTeamPage"),
    "research": ("research", "ResearchWorkbenchPage"),
}

EXPECTED_PAGE_FILES = {
    "IntelDashboardPage": ROOT / "frontend" / "src" / "pages" / "IntelDashboardPage.tsx",
    "ReviewQueuePage": ROOT / "frontend" / "src" / "pages" / "ReviewQueuePage.tsx",
    "CandidateQueuePage": ROOT / "frontend" / "src" / "pages" / "CandidateQueuePage.tsx",
    "RecipeBuilderPage": ROOT / "frontend" / "src" / "pages" / "RecipeBuilderPage.tsx",
    "RunConsolePage": ROOT / "frontend" / "src" / "pages" / "RunConsolePage.tsx",
    "AuthorizationCenterPage": ROOT / "frontend" / "src" / "pages" / "AuthorizationCenterPage.tsx",
    "AttackCoveragePage": ROOT / "frontend" / "src" / "pages" / "AttackCoveragePage.tsx",
    "CaseGraphPage": ROOT / "frontend" / "src" / "pages" / "CaseGraphPage.tsx",
    "AutonomousAgentPage": ROOT / "frontend" / "src" / "pages" / "AutonomousAgentPage.tsx",
    "EvidenceExplorerPage": ROOT / "frontend" / "src" / "pages" / "EvidenceExplorerPage.tsx",
    "ArtifactForgePage": ROOT / "frontend" / "src" / "pages" / "ArtifactForgePage.tsx",
    "ProvenanceCenterPage": ROOT / "frontend" / "src" / "pages" / "ProvenanceCenterPage.tsx",
    "AnalystLedgerPage": ROOT / "frontend" / "src" / "pages" / "AnalystLedgerPage.tsx",
    "DisclosureBundlesPage": ROOT / "frontend" / "src" / "pages" / "DisclosureBundlesPage.tsx",
    "SpecimenIntakePage": ROOT / "frontend" / "src" / "pages" / "SpecimenIntakePage.tsx",
    "AnalysisCasesPage": ROOT / "frontend" / "src" / "pages" / "AnalysisCasesPage.tsx",
    "SandboxProfilesPage": ROOT / "frontend" / "src" / "pages" / "SandboxProfilesPage.tsx",
    "BehaviorFindingsPage": ROOT / "frontend" / "src" / "pages" / "BehaviorFindingsPage.tsx",
    "IndicatorForgeV3Page": ROOT / "frontend" / "src" / "pages" / "IndicatorForgeV3Page.tsx",
    "PreventionForgeV3Page": ROOT / "frontend" / "src" / "pages" / "PreventionForgeV3Page.tsx",
    "DefangQueuePage": ROOT / "frontend" / "src" / "pages" / "DefangQueuePage.tsx",
    "MalwareReportsPage": ROOT / "frontend" / "src" / "pages" / "MalwareReportsPage.tsx",
    "AISessionsPage": ROOT / "frontend" / "src" / "pages" / "AISessionsPage.tsx",
    "PolicyCenterPage": ROOT / "frontend" / "src" / "pages" / "PolicyCenterPage.tsx",
    "WorkerFleetPage": ROOT / "frontend" / "src" / "pages" / "WorkerFleetPage.tsx",
    "TeamAnalyticsPage": ROOT / "frontend" / "src" / "pages" / "TeamAnalyticsPage.tsx",
    "PurpleTeamPage": ROOT / "frontend" / "src" / "pages" / "PurpleTeamPage.tsx",
    "ResearchWorkbenchPage": ROOT / "frontend" / "src" / "pages" / "ResearchWorkbenchPage.tsx",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    app_text = APP_TSX.read_text()
    layout_text = LAYOUT_TSX.read_text()
    report: list[str] = []

    for route, (permission_key, component) in EXPECTED_ROUTES.items():
        if route == "/":
            needle = f'<Route index element={{gated("{permission_key}", <{component} />)}} />'
        else:
            needle = f'<Route path="{route}" element={{gated("{permission_key}", <{component} />)}} />'
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
        "/case-graph",
        "/autonomous",
        "/evidence",
        "/artifacts",
        "/provenance",
        "/ledger",
        "/disclosures",
        "/specimens",
        "/analysis-cases",
        "/sandbox-profiles",
        "/findings",
        "/indicators",
        "/prevention-v3",
        "/defang",
        "/reports",
        "/ai-sessions",
        "/policy",
        "/workers",
        "/analytics",
        "/purple-team",
        "/research",
    ]:
        require(f'{{ to: "{nav_path}"' in layout_text, f"missing nav config entry for {nav_path}")
        report.append(f"nav link present for {nav_path}")

    print("Sheshnaag frontend route smoke summary")
    for line in report:
        print(f"- {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
