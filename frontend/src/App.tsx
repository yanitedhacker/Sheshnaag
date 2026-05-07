import { Routes, Route } from "react-router-dom";
import { Layout } from "./components/Layout";
import { RoleGate } from "./components/RoleGate";
import { ROUTE_PERMISSIONS } from "./permissions";
import type { PermissionSlug } from "./permissions";
import { AnalystLedgerPage } from "./pages/AnalystLedgerPage";
import { AISessionsPage } from "./pages/AISessionsPage";
import { AnalysisCasesPage } from "./pages/AnalysisCasesPage";
import { AttackCoveragePage } from "./pages/AttackCoveragePage";
import { ArtifactForgePage } from "./pages/ArtifactForgePage";
import { AuthorizationCenterPage } from "./pages/AuthorizationCenterPage";
import { AutonomousAgentPage } from "./pages/AutonomousAgentPage";
import { CaseGraphPage } from "./pages/CaseGraphPage";
import { BehaviorFindingsPage } from "./pages/BehaviorFindingsPage";
import { CandidateQueuePage } from "./pages/CandidateQueuePage";
import { DefangQueuePage } from "./pages/DefangQueuePage";
import { DisclosureBundlesPage } from "./pages/DisclosureBundlesPage";
import { EvidenceExplorerPage } from "./pages/EvidenceExplorerPage";
import { IntelDashboardPage } from "./pages/IntelDashboardPage";
import { IndicatorForgeV3Page } from "./pages/IndicatorForgeV3Page";
import { MalwareReportsPage } from "./pages/MalwareReportsPage";
import { NotAuthorizedPage } from "./pages/NotAuthorizedPage";
import { PolicyCenterPage } from "./pages/PolicyCenterPage";
import { PreventionForgeV3Page } from "./pages/PreventionForgeV3Page";
import { ProvenanceCenterPage } from "./pages/ProvenanceCenterPage";
import { RecipeBuilderPage } from "./pages/RecipeBuilderPage";
import { ReviewQueuePage } from "./pages/ReviewQueuePage";
import { RunConsolePage } from "./pages/RunConsolePage";
import { SandboxProfilesPage } from "./pages/SandboxProfilesPage";
import { SpecimenIntakePage } from "./pages/SpecimenIntakePage";
import { TeamAnalyticsPage } from "./pages/TeamAnalyticsPage";
import { WorkerFleetPage } from "./pages/WorkerFleetPage";

import type { ReactNode } from "react";


function gated(path: keyof typeof ROUTE_PERMISSIONS, element: ReactNode): ReactNode {
  const permission: PermissionSlug = ROUTE_PERMISSIONS[path];
  return (
    <RoleGate permission={permission} fallback={<NotAuthorizedPage />}>
      {element}
    </RoleGate>
  );
}


export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={gated("intel", <IntelDashboardPage />)} />
        <Route path="intel" element={gated("intel", <IntelDashboardPage />)} />
        <Route path="review" element={gated("review", <ReviewQueuePage />)} />
        <Route path="candidates" element={gated("candidates", <CandidateQueuePage />)} />
        <Route path="recipes" element={gated("recipes", <RecipeBuilderPage />)} />
        <Route path="runs" element={gated("runs", <RunConsolePage />)} />
        <Route path="authorization" element={gated("authorization", <AuthorizationCenterPage />)} />
        <Route path="attack-coverage" element={gated("attack-coverage", <AttackCoveragePage />)} />
        <Route path="case-graph" element={gated("case-graph", <CaseGraphPage />)} />
        <Route path="autonomous" element={gated("autonomous", <AutonomousAgentPage />)} />
        <Route path="evidence" element={gated("evidence", <EvidenceExplorerPage />)} />
        <Route path="artifacts" element={gated("artifacts", <ArtifactForgePage />)} />
        <Route path="provenance" element={gated("provenance", <ProvenanceCenterPage />)} />
        <Route path="ledger" element={gated("ledger", <AnalystLedgerPage />)} />
        <Route path="disclosures" element={gated("disclosures", <DisclosureBundlesPage />)} />
        <Route path="specimens" element={gated("specimens", <SpecimenIntakePage />)} />
        <Route path="analysis-cases" element={gated("analysis-cases", <AnalysisCasesPage />)} />
        <Route path="sandbox-profiles" element={gated("sandbox-profiles", <SandboxProfilesPage />)} />
        <Route path="findings" element={gated("findings", <BehaviorFindingsPage />)} />
        <Route path="indicators" element={gated("indicators", <IndicatorForgeV3Page />)} />
        <Route path="prevention-v3" element={gated("prevention-v3", <PreventionForgeV3Page />)} />
        <Route path="defang" element={gated("defang", <DefangQueuePage />)} />
        <Route path="reports" element={gated("reports", <MalwareReportsPage />)} />
        <Route path="ai-sessions" element={gated("ai-sessions", <AISessionsPage />)} />
        <Route path="policy" element={gated("policy", <PolicyCenterPage />)} />
        <Route path="workers" element={gated("workers", <WorkerFleetPage />)} />
        <Route path="analytics" element={gated("analytics", <TeamAnalyticsPage />)} />
        <Route path="not-authorized" element={<NotAuthorizedPage />} />
        <Route path="*" element={gated("intel", <IntelDashboardPage />)} />
      </Route>
    </Routes>
  );
}
