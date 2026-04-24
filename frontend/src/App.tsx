import { Routes, Route } from "react-router-dom";
import { Layout } from "./components/Layout";
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
import { PolicyCenterPage } from "./pages/PolicyCenterPage";
import { PreventionForgeV3Page } from "./pages/PreventionForgeV3Page";
import { ProvenanceCenterPage } from "./pages/ProvenanceCenterPage";
import { RecipeBuilderPage } from "./pages/RecipeBuilderPage";
import { ReviewQueuePage } from "./pages/ReviewQueuePage";
import { RunConsolePage } from "./pages/RunConsolePage";
import { SandboxProfilesPage } from "./pages/SandboxProfilesPage";
import { SpecimenIntakePage } from "./pages/SpecimenIntakePage";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<IntelDashboardPage />} />
        <Route path="intel" element={<IntelDashboardPage />} />
        <Route path="review" element={<ReviewQueuePage />} />
        <Route path="candidates" element={<CandidateQueuePage />} />
        <Route path="recipes" element={<RecipeBuilderPage />} />
        <Route path="runs" element={<RunConsolePage />} />
        <Route path="authorization" element={<AuthorizationCenterPage />} />
        <Route path="attack-coverage" element={<AttackCoveragePage />} />
        <Route path="case-graph" element={<CaseGraphPage />} />
        <Route path="autonomous" element={<AutonomousAgentPage />} />
        <Route path="evidence" element={<EvidenceExplorerPage />} />
        <Route path="artifacts" element={<ArtifactForgePage />} />
        <Route path="provenance" element={<ProvenanceCenterPage />} />
        <Route path="ledger" element={<AnalystLedgerPage />} />
        <Route path="disclosures" element={<DisclosureBundlesPage />} />
        <Route path="specimens" element={<SpecimenIntakePage />} />
        <Route path="analysis-cases" element={<AnalysisCasesPage />} />
        <Route path="sandbox-profiles" element={<SandboxProfilesPage />} />
        <Route path="findings" element={<BehaviorFindingsPage />} />
        <Route path="indicators" element={<IndicatorForgeV3Page />} />
        <Route path="prevention-v3" element={<PreventionForgeV3Page />} />
        <Route path="defang" element={<DefangQueuePage />} />
        <Route path="reports" element={<MalwareReportsPage />} />
        <Route path="ai-sessions" element={<AISessionsPage />} />
        <Route path="policy" element={<PolicyCenterPage />} />
        <Route path="*" element={<IntelDashboardPage />} />
      </Route>
    </Routes>
  );
}
