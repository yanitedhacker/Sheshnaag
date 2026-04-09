import { Routes, Route } from "react-router-dom";
import { Layout } from "./components/Layout";
import { AnalystLedgerPage } from "./pages/AnalystLedgerPage";
import { ArtifactForgePage } from "./pages/ArtifactForgePage";
import { CandidateQueuePage } from "./pages/CandidateQueuePage";
import { DisclosureBundlesPage } from "./pages/DisclosureBundlesPage";
import { EvidenceExplorerPage } from "./pages/EvidenceExplorerPage";
import { IntelDashboardPage } from "./pages/IntelDashboardPage";
import { ProvenanceCenterPage } from "./pages/ProvenanceCenterPage";
import { RecipeBuilderPage } from "./pages/RecipeBuilderPage";
import { ReviewQueuePage } from "./pages/ReviewQueuePage";
import { RunConsolePage } from "./pages/RunConsolePage";

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
        <Route path="evidence" element={<EvidenceExplorerPage />} />
        <Route path="artifacts" element={<ArtifactForgePage />} />
        <Route path="provenance" element={<ProvenanceCenterPage />} />
        <Route path="ledger" element={<AnalystLedgerPage />} />
        <Route path="disclosures" element={<DisclosureBundlesPage />} />
        <Route path="*" element={<IntelDashboardPage />} />
      </Route>
    </Routes>
  );
}
