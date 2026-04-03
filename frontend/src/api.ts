import type {
  ApprovalResponse,
  AssetDetail,
  AssetListResponse,
  AssetVulnerability,
  AuditResponse,
  CopilotResponse,
  CveDetail,
  DashboardResponse,
  FeedbackResponse,
  GraphResponse,
  ImportResponse,
  ModelTrustResponse,
  PatchDetail,
  SimulationResponse,
  TenantListResponse,
  TenantOnboardResponse,
  WorkbenchSummary,
} from "./types";

const API_BASE = "";

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    ...init,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export const api = {
  getDashboard: () => fetchJson<DashboardResponse>("/api/dashboard"),
  getWorkbench: () => fetchJson<WorkbenchSummary>("/api/workbench/summary?tenant_slug=demo-public&limit=20"),
  getGraph: (assetId?: number, cveId?: string) => {
    const params = new URLSearchParams({ tenant_slug: "demo-public", limit: "8" });
    if (assetId) params.set("asset_id", String(assetId));
    if (cveId) params.set("cve_id", cveId);
    return fetchJson<GraphResponse>(`/api/graph/attack-paths?${params.toString()}`);
  },
  getAssets: () => fetchJson<AssetListResponse>("/api/assets?tenant_slug=demo-public&page_size=50"),
  getAsset: (assetId: number) => fetchJson<AssetDetail>(`/api/assets/${assetId}`),
  getAssetVulnerabilities: (assetId: number) => fetchJson<AssetVulnerability[]>(`/api/assets/${assetId}/vulnerabilities`),
  getCve: (cveId: string) => fetchJson<CveDetail>(`/api/cves/${cveId}`),
  getPatch: (patchId: string) => fetchJson<PatchDetail>(`/api/patches/${patchId}`),
  runSimulation: (payload: Record<string, unknown>) =>
    fetchJson<SimulationResponse>("/api/simulations/risk", { method: "POST", body: JSON.stringify(payload) }),
  queryCopilot: (query: string) =>
    fetchJson<CopilotResponse>("/api/copilot/query", {
      method: "POST",
      body: JSON.stringify({ query, tenant_slug: "demo-public" }),
    }),
  getModelTrust: () => fetchJson<ModelTrustResponse>("/api/model/trust"),
  getApprovals: () => fetchJson<ApprovalResponse>("/api/governance/approvals?tenant_slug=demo-public"),
  getAudit: () => fetchJson<AuditResponse>("/api/governance/audit?tenant_slug=demo-public"),
  getFeedback: () => fetchJson<FeedbackResponse>("/api/model/feedback?tenant_slug=demo-public"),
  getTenants: () => fetchJson<TenantListResponse>("/api/tenants"),
  onboardTenant: (payload: Record<string, unknown>) =>
    fetchJson<TenantOnboardResponse>("/api/tenants/onboard", { method: "POST", body: JSON.stringify(payload) }),
  importSbom: (payload: Record<string, unknown>) =>
    fetchJson<ImportResponse>("/api/imports/sbom", { method: "POST", body: JSON.stringify(payload) }),
  importVex: (payload: Record<string, unknown>) =>
    fetchJson<ImportResponse>("/api/imports/vex", { method: "POST", body: JSON.stringify(payload) }),
};
