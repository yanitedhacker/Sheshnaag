import type {
  ApprovalResponse,
  ArtifactListResponse,
  AssetDetail,
  AssetListResponse,
  AssetVulnerability,
  CandidateItem,
  CandidateListResponse,
  CandidateWorkloadResponse,
  AuditResponse,
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
  TemplateListResponse,
  TenantListResponse,
  TenantOnboardResponse,
  SupplyChainOverviewResponse,
  WorkbenchSummary,
} from "./types";

const API_BASE = "";
const WORKSPACE_SLUG_KEY = "sheshnaag.workspace.slug";

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

async function getWritableTenantSlug(): Promise<string> {
  if (typeof window === "undefined") {
    return "demo-public";
  }
  const existing = window.localStorage.getItem(WORKSPACE_SLUG_KEY);
  if (existing) {
    return existing;
  }
  const tenants = await fetchJson<TenantListResponse>("/api/tenants");
  const writable = tenants.items.find((item) => !item.is_read_only);
  if (writable?.tenant_slug) {
    window.localStorage.setItem(WORKSPACE_SLUG_KEY, writable.tenant_slug);
    return writable.tenant_slug;
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
  window.localStorage.setItem(WORKSPACE_SLUG_KEY, onboarded.tenant.slug);
  return onboarded.tenant.slug;
}

async function withWritableTenant(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  if (payload.tenant_slug || payload.tenant_id) {
    return payload;
  }
  return { ...payload, tenant_slug: await getWritableTenantSlug() };
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

  // Intel + candidates
  getIntelOverview: () => fetchJson<IntelOverviewResponse>("/api/intel/overview?tenant_slug=demo-public"),
  getCandidates: (params?: Record<string, string | number | boolean | undefined>) => {
    const search = new URLSearchParams({ tenant_slug: "demo-public" });
    Object.entries(params ?? {}).forEach(([key, value]) => {
      if (value !== undefined && value !== "") {
        search.set(key, String(value));
      }
    });
    return fetchJson<CandidateListResponse>(`/api/candidates?${search.toString()}`);
  },
  getCandidate: (candidateId: number) => fetchJson<CandidateItem>(`/api/candidates/${candidateId}?tenant_slug=demo-public`),
  getCandidateWorkload: () => fetchJson<CandidateWorkloadResponse>("/api/candidates/workload/summary?tenant_slug=demo-public"),
  assignCandidate: (candidateId: number, payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<CandidateItem>(`/api/candidates/${candidateId}/assign`, { method: "POST", body: JSON.stringify(body) })),
  deferCandidate: (candidateId: number, payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<CandidateItem>(`/api/candidates/${candidateId}/defer`, { method: "POST", body: JSON.stringify(body) })),
  rejectCandidate: (candidateId: number, payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<CandidateItem>(`/api/candidates/${candidateId}/reject`, { method: "POST", body: JSON.stringify(body) })),
  restoreCandidate: (candidateId: number, payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<CandidateItem>(`/api/candidates/${candidateId}/restore`, { method: "POST", body: JSON.stringify(body) })),
  archiveCandidate: (candidateId: number, payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<CandidateItem>(`/api/candidates/${candidateId}/archive`, { method: "POST", body: JSON.stringify(body) })),
  mergeCandidateDuplicate: (candidateId: number, payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<{ merged: CandidateItem; target: CandidateItem }>(
        `/api/candidates/${candidateId}/merge`,
        { method: "POST", body: JSON.stringify(body) },
      )),

  // Recipe APIs
  listRecipes: () => fetchJson<RecipeListResponse>("/api/recipes?tenant_slug=demo-public"),
  getRecipe: (recipeId: number) => fetchJson<Recipe>(`/api/recipes/${recipeId}?tenant_slug=demo-public`),
  createRecipe: (payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<Recipe>("/api/recipes", { method: "POST", body: JSON.stringify(body) })),
  addRecipeRevision: (recipeId: number, payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<Recipe>(`/api/recipes/${recipeId}/revisions`, { method: "POST", body: JSON.stringify(body) })),
  approveRecipeRevision: (recipeId: number, revisionNumber: number, payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<Recipe>(
        `/api/recipes/${recipeId}/revisions/${revisionNumber}/approve`,
        { method: "POST", body: JSON.stringify(body) },
      )),
  lintRecipe: (payload: Record<string, unknown>) =>
    fetchJson<RecipeLintResult>("/api/recipes/lint", { method: "POST", body: JSON.stringify(payload) }),
  diffRecipeRevisions: (recipeId: number, oldRev: number, newRev: number) =>
    fetchJson<RecipeDiffResult>(
      `/api/recipes/${recipeId}/diff?old_revision=${oldRev}&new_revision=${newRev}&tenant_slug=demo-public`,
    ),

  // Run APIs
  listRuns: () => fetchJson<RunListResponse>("/api/runs?tenant_slug=demo-public"),
  getRun: (runId: number) => fetchJson<RunDetailResponse>(`/api/runs/${runId}?tenant_slug=demo-public`),
  getRunHealth: (runId: number) => fetchJson<RunHealthResponse>(`/api/runs/${runId}/health?tenant_slug=demo-public`),
  stopRun: (runId: number, payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<RunDetailResponse>(`/api/runs/${runId}/stop`, { method: "POST", body: JSON.stringify(body) })),
  teardownRun: (runId: number, payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<RunDetailResponse>(`/api/runs/${runId}/teardown`, { method: "POST", body: JSON.stringify(body) })),
  destroyRun: (runId: number, payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<RunDetailResponse>(`/api/runs/${runId}/destroy`, { method: "POST", body: JSON.stringify(body) })),
  launchRun: (payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<RunDetailResponse>("/api/runs", { method: "POST", body: JSON.stringify(body) })),

  // Template APIs
  listTemplates: () => fetchJson<TemplateListResponse>("/api/templates?tenant_slug=demo-public"),

  // Evidence, artifacts, provenance, ledger, bundles
  listEvidence: (runId?: number) =>
    fetchJson<EvidenceListResponse>(`/api/evidence?tenant_slug=demo-public${runId ? `&run_id=${runId}` : ""}`),
  listArtifacts: (runId?: number) =>
    fetchJson<ArtifactListResponse>(`/api/artifacts?tenant_slug=demo-public${runId ? `&run_id=${runId}` : ""}`),
  reviewArtifact: (payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<Record<string, unknown>>("/api/artifacts/review", { method: "POST", body: JSON.stringify(body) })),
  addArtifactFeedback: (payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<Record<string, unknown>>("/api/artifacts/feedback", { method: "POST", body: JSON.stringify(body) })),
  getProvenance: (runId?: number) =>
    fetchJson<ProvenanceResponse>(`/api/provenance?tenant_slug=demo-public${runId ? `&run_id=${runId}` : ""}`),
  getLedger: () => fetchJson<LedgerResponse>("/api/ledger?tenant_slug=demo-public"),
  listDisclosures: () => fetchJson<DisclosureListResponse>("/api/disclosures?tenant_slug=demo-public"),
  createDisclosureBundle: (payload: Record<string, unknown>) =>
    withWritableTenant(payload).then((body) =>
      fetchJson<DisclosureBundleRecord>("/api/disclosures", { method: "POST", body: JSON.stringify(body) })),
};
