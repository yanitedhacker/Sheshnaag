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
  Recipe,
  RecipeDiffResult,
  RecipeLintResult,
  RecipeListResponse,
  RunHealthResponse,
  RunListResponse,
  RunSummary,
  SimulationResponse,
  TemplateListResponse,
  TenantListResponse,
  TenantOnboardResponse,
  SupplyChainOverviewResponse,
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
  getSupplyChainOverview: () =>
    fetchJson<SupplyChainOverviewResponse>("/api/supply-chain/overview?tenant_slug=demo-public"),
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

  // Recipe APIs
  listRecipes: () => fetchJson<RecipeListResponse>("/api/recipes?tenant_slug=demo-public"),
  getRecipe: (recipeId: number) => fetchJson<Recipe>(`/api/recipes/${recipeId}?tenant_slug=demo-public`),
  createRecipe: (payload: Record<string, unknown>) =>
    fetchJson<Recipe>("/api/recipes", { method: "POST", body: JSON.stringify(payload) }),
  addRecipeRevision: (recipeId: number, payload: Record<string, unknown>) =>
    fetchJson<Recipe>(`/api/recipes/${recipeId}/revisions`, { method: "POST", body: JSON.stringify(payload) }),
  approveRecipeRevision: (recipeId: number, revisionNumber: number, payload: Record<string, unknown>) =>
    fetchJson<Recipe>(
      `/api/recipes/${recipeId}/revisions/${revisionNumber}/approve`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  lintRecipe: (payload: Record<string, unknown>) =>
    fetchJson<RecipeLintResult>("/api/recipes/lint", { method: "POST", body: JSON.stringify(payload) }),
  diffRecipeRevisions: (recipeId: number, oldRev: number, newRev: number) =>
    fetchJson<RecipeDiffResult>(
      `/api/recipes/${recipeId}/diff?old_revision=${oldRev}&new_revision=${newRev}&tenant_slug=demo-public`,
    ),

  // Run APIs
  listRuns: () => fetchJson<RunListResponse>("/api/runs?tenant_slug=demo-public"),
  getRun: (runId: number) => fetchJson<RunSummary>(`/api/runs/${runId}?tenant_slug=demo-public`),
  getRunHealth: (runId: number) => fetchJson<RunHealthResponse>(`/api/runs/${runId}/health?tenant_slug=demo-public`),
  stopRun: (runId: number, payload: Record<string, unknown>) =>
    fetchJson<RunSummary>(`/api/runs/${runId}/stop`, { method: "POST", body: JSON.stringify(payload) }),
  teardownRun: (runId: number, payload: Record<string, unknown>) =>
    fetchJson<RunSummary>(`/api/runs/${runId}/teardown`, { method: "POST", body: JSON.stringify(payload) }),
  destroyRun: (runId: number, payload: Record<string, unknown>) =>
    fetchJson<RunSummary>(`/api/runs/${runId}/destroy`, { method: "POST", body: JSON.stringify(payload) }),
  launchRun: (payload: Record<string, unknown>) =>
    fetchJson<RunSummary>("/api/runs", { method: "POST", body: JSON.stringify(payload) }),

  // Template APIs
  listTemplates: () => fetchJson<TemplateListResponse>("/api/templates?tenant_slug=demo-public"),
};
