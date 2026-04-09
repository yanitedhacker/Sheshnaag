import type {
  ApprovalResponse,
  ArtifactListResponse,
  AssetDetail,
  AssetListResponse,
  AssetVulnerability,
  AuditResponse,
  CandidateItem,
  CandidateListResponse,
  CandidateWorkloadResponse,
  CopilotResponse,
  CveDetail,
  DashboardResponse,
  DisclosureBundleRecord,
  DisclosureListResponse,
  EvidenceListResponse,
  FeedbackResponse,
  GraphResponse,
  ImportResponse,
  IntelOverviewResponse,
  LedgerResponse,
  ModelTrustResponse,
  PatchDetail,
  ProvenanceResponse,
  Recipe,
  RecipeDiffResult,
  RecipeLintResult,
  RecipeListResponse,
  RunDetailResponse,
  RunHealthResponse,
  RunListResponse,
  SimulationResponse,
  SupplyChainOverviewResponse,
  TemplateListResponse,
  TenantListResponse,
  TenantOnboardResponse,
  WorkbenchSummary,
} from "./types";

const API_BASE = "";
export const WORKSPACE_SLUG_KEY = "sheshnaag.workspace.slug";

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

export function readStoredWorkspaceSlug(): string | null {
  if (typeof window === "undefined") {
    return null;
  }
  return window.localStorage.getItem(WORKSPACE_SLUG_KEY);
}

export function storeWorkspaceSlug(slug: string): void {
  if (typeof window === "undefined") {
    return;
  }
  window.localStorage.setItem(WORKSPACE_SLUG_KEY, slug);
}

export async function getTenants(): Promise<TenantListResponse> {
  return fetchJson<TenantListResponse>("/api/tenants");
}

export async function getActiveTenantSlug(): Promise<string> {
  if (typeof window === "undefined") {
    return "demo-public";
  }
  const existing = readStoredWorkspaceSlug();
  if (existing) {
    return existing;
  }

  const tenants = await getTenants();
  const preferred = tenants.items.find((item) => !item.is_read_only) ?? tenants.items[0];
  if (preferred?.tenant_slug) {
    storeWorkspaceSlug(preferred.tenant_slug);
    return preferred.tenant_slug;
  }

  const slug = `codex-${Date.now()}`;
  const onboarded = await fetchJson<TenantOnboardResponse>("/api/tenants/onboard", {
    method: "POST",
    body: JSON.stringify({
      tenant_name: "Sheshnaag Operator Workspace",
      tenant_slug: slug,
      admin_email: "codex.operator@sheshnaag.local",
      admin_password: "codex-operator-123",
      admin_name: "Codex Operator",
      description: "Auto-provisioned local workspace for the operator UI.",
    }),
  });
  storeWorkspaceSlug(onboarded.tenant.slug);
  return onboarded.tenant.slug;
}

async function withActiveTenant(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  if (payload.tenant_slug || payload.tenant_id) {
    return payload;
  }
  return { ...payload, tenant_slug: await getActiveTenantSlug() };
}

async function tenantPath(path: string, params?: Record<string, string | number | boolean | undefined>): Promise<string> {
  const tenantSlug = await getActiveTenantSlug();
  const search = new URLSearchParams({ tenant_slug: tenantSlug });
  Object.entries(params ?? {}).forEach(([key, value]) => {
    if (value !== undefined && value !== "") {
      search.set(key, String(value));
    }
  });
  return `${path}?${search.toString()}`;
}

async function fetchTenantJson<T>(
  path: string,
  params?: Record<string, string | number | boolean | undefined>,
): Promise<T> {
  return fetchJson<T>(await tenantPath(path, params));
}

export const api = {
  getDashboard: () => fetchJson<DashboardResponse>("/api/dashboard"),
  getWorkbench: () => fetchTenantJson<WorkbenchSummary>("/api/workbench/summary", { limit: 20 }),
  getGraph: async (assetId?: number, cveId?: string) => {
    const params: Record<string, string | number | boolean | undefined> = { limit: 8 };
    if (assetId) params.asset_id = assetId;
    if (cveId) params.cve_id = cveId;
    return fetchTenantJson<GraphResponse>("/api/graph/attack-paths", params);
  },
  getAssets: () => fetchTenantJson<AssetListResponse>("/api/assets", { page_size: 50 }),
  getAsset: (assetId: number) => fetchJson<AssetDetail>(`/api/assets/${assetId}`),
  getAssetVulnerabilities: (assetId: number) => fetchJson<AssetVulnerability[]>(`/api/assets/${assetId}/vulnerabilities`),
  getCve: (cveId: string) => fetchJson<CveDetail>(`/api/cves/${cveId}`),
  getPatch: (patchId: string) => fetchJson<PatchDetail>(`/api/patches/${patchId}`),
  runSimulation: async (payload: Record<string, unknown>) =>
    fetchJson<SimulationResponse>("/api/simulations/risk", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  queryCopilot: async (query: string) =>
    fetchJson<CopilotResponse>("/api/copilot/query", {
      method: "POST",
      body: JSON.stringify({ query, tenant_slug: await getActiveTenantSlug() }),
    }),
  getModelTrust: () => fetchJson<ModelTrustResponse>("/api/model/trust"),
  getSupplyChainOverview: () => fetchTenantJson<SupplyChainOverviewResponse>("/api/supply-chain/overview"),
  getApprovals: () => fetchTenantJson<ApprovalResponse>("/api/governance/approvals"),
  getAudit: () => fetchTenantJson<AuditResponse>("/api/governance/audit"),
  getFeedback: () => fetchTenantJson<FeedbackResponse>("/api/model/feedback"),
  getTenants,
  onboardTenant: (payload: Record<string, unknown>) =>
    fetchJson<TenantOnboardResponse>("/api/tenants/onboard", { method: "POST", body: JSON.stringify(payload) }),
  importSbom: async (payload: Record<string, unknown>) =>
    fetchJson<ImportResponse>("/api/imports/sbom", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  importVex: async (payload: Record<string, unknown>) =>
    fetchJson<ImportResponse>("/api/imports/vex", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),

  getIntelOverview: () => fetchTenantJson<IntelOverviewResponse>("/api/intel/overview"),
  getCandidates: (params?: Record<string, string | number | boolean | undefined>) =>
    fetchTenantJson<CandidateListResponse>("/api/candidates", params),
  getCandidate: async (candidateId: number) => fetchJson<CandidateItem>(await tenantPath(`/api/candidates/${candidateId}`)),
  getCandidateWorkload: () => fetchTenantJson<CandidateWorkloadResponse>("/api/candidates/workload/summary"),
  assignCandidate: async (candidateId: number, payload: Record<string, unknown>) =>
    fetchJson<CandidateItem>(`/api/candidates/${candidateId}/assign`, { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  deferCandidate: async (candidateId: number, payload: Record<string, unknown>) =>
    fetchJson<CandidateItem>(`/api/candidates/${candidateId}/defer`, { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  rejectCandidate: async (candidateId: number, payload: Record<string, unknown>) =>
    fetchJson<CandidateItem>(`/api/candidates/${candidateId}/reject`, { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  restoreCandidate: async (candidateId: number, payload: Record<string, unknown>) =>
    fetchJson<CandidateItem>(`/api/candidates/${candidateId}/restore`, { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  archiveCandidate: async (candidateId: number, payload: Record<string, unknown>) =>
    fetchJson<CandidateItem>(`/api/candidates/${candidateId}/archive`, { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  mergeCandidateDuplicate: async (candidateId: number, payload: Record<string, unknown>) =>
    fetchJson<{ merged: CandidateItem; target: CandidateItem }>(`/api/candidates/${candidateId}/merge`, {
      method: "POST",
      body: JSON.stringify(await withActiveTenant(payload)),
    }),

  listRecipes: () => fetchTenantJson<RecipeListResponse>("/api/recipes"),
  getRecipe: async (recipeId: number) => fetchJson<Recipe>(await tenantPath(`/api/recipes/${recipeId}`)),
  createRecipe: async (payload: Record<string, unknown>) =>
    fetchJson<Recipe>("/api/recipes", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  addRecipeRevision: async (recipeId: number, payload: Record<string, unknown>) =>
    fetchJson<Recipe>(`/api/recipes/${recipeId}/revisions`, { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  approveRecipeRevision: async (recipeId: number, revisionNumber: number, payload: Record<string, unknown>) =>
    fetchJson<Recipe>(`/api/recipes/${recipeId}/revisions/${revisionNumber}/approve`, {
      method: "POST",
      body: JSON.stringify(await withActiveTenant(payload)),
    }),
  lintRecipe: (payload: Record<string, unknown>) =>
    fetchJson<RecipeLintResult>("/api/recipes/lint", { method: "POST", body: JSON.stringify(payload) }),
  diffRecipeRevisions: async (recipeId: number, oldRev: number, newRev: number) =>
    fetchJson<RecipeDiffResult>(await tenantPath(`/api/recipes/${recipeId}/diff`, { old_revision: oldRev, new_revision: newRev })),

  listRuns: () => fetchTenantJson<RunListResponse>("/api/runs"),
  getRun: async (runId: number) => fetchJson<RunDetailResponse>(await tenantPath(`/api/runs/${runId}`)),
  getRunHealth: async (runId: number) => fetchJson<RunHealthResponse>(await tenantPath(`/api/runs/${runId}/health`)),
  planRun: async (payload: Record<string, unknown>) =>
    fetchJson<RunDetailResponse>("/api/runs/plan", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  allocateRunResources: async (runId: number, payload: Record<string, unknown>) =>
    fetchJson<RunDetailResponse>(`/api/runs/${runId}/allocate`, { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  bootRun: async (runId: number, payload: Record<string, unknown>) =>
    fetchJson<RunDetailResponse>(`/api/runs/${runId}/boot`, { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  stopRun: async (runId: number, payload: Record<string, unknown>) =>
    fetchJson<RunDetailResponse>(`/api/runs/${runId}/stop`, { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  teardownRun: async (runId: number, payload: Record<string, unknown>) =>
    fetchJson<RunDetailResponse>(`/api/runs/${runId}/teardown`, { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  destroyRun: async (runId: number, payload: Record<string, unknown>) =>
    fetchJson<RunDetailResponse>(`/api/runs/${runId}/destroy`, { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  launchRun: async (payload: Record<string, unknown>) =>
    fetchJson<RunDetailResponse>("/api/runs", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),

  listTemplates: () => fetchTenantJson<TemplateListResponse>("/api/templates"),

  listEvidence: (runId?: number) => fetchTenantJson<EvidenceListResponse>("/api/evidence", runId ? { run_id: runId } : undefined),
  listArtifacts: (runId?: number) => fetchTenantJson<ArtifactListResponse>("/api/artifacts", runId ? { run_id: runId } : undefined),
  reviewArtifact: async (payload: Record<string, unknown>) =>
    fetchJson<Record<string, unknown>>("/api/artifacts/review", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  addArtifactFeedback: async (payload: Record<string, unknown>) =>
    fetchJson<Record<string, unknown>>("/api/artifacts/feedback", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  getProvenance: (runId?: number) => fetchTenantJson<ProvenanceResponse>("/api/provenance", runId ? { run_id: runId } : undefined),
  getLedger: () => fetchTenantJson<LedgerResponse>("/api/ledger"),
  listDisclosures: () => fetchTenantJson<DisclosureListResponse>("/api/disclosures"),
  createDisclosureBundle: async (payload: Record<string, unknown>) =>
    fetchJson<DisclosureBundleRecord>("/api/disclosures", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
};
