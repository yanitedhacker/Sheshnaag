import { Routes, Route } from "react-router-dom";
import { Layout } from "./components/Layout";
import { WorkbenchPage } from "./pages/WorkbenchPage";
import { AttackGraphPage } from "./pages/AttackGraphPage";
import { SimulatorPage } from "./pages/SimulatorPage";
import { AssetExplorerPage } from "./pages/AssetExplorerPage";
import { CveDetailPage } from "./pages/CveDetailPage";
import { PatchDetailPage } from "./pages/PatchDetailPage";
import { TrustCenterPage } from "./pages/TrustCenterPage";
import { OperationsPage } from "./pages/OperationsPage";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<WorkbenchPage />} />
        <Route path="graph" element={<AttackGraphPage />} />
        <Route path="simulator" element={<SimulatorPage />} />
        <Route path="assets" element={<AssetExplorerPage />} />
        <Route path="cves/:cveId" element={<CveDetailPage />} />
        <Route path="patches/:patchId" element={<PatchDetailPage />} />
        <Route path="trust" element={<TrustCenterPage />} />
        <Route path="operations" element={<OperationsPage />} />
      </Route>
    </Routes>
  );
}
