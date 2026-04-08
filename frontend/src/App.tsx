import { Routes, Route } from "react-router-dom";
import { Layout } from "./components/Layout";
import { SupplyChainStoryPage } from "./pages/SupplyChainStoryPage";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<SupplyChainStoryPage />} />
        <Route path="*" element={<SupplyChainStoryPage />} />
      </Route>
    </Routes>
  );
}
