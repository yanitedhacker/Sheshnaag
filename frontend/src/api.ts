import type {
  ApprovalResponse,
  AttackCoverageResponse,
  AttackTechniqueFindingsResponse,
  ArtifactListResponse,
  AuthorizationArtifact,
  AuthorizationChainRootResponse,
  AuthorizationChainVerifyResponse,
  AuthorizationListResponse,
  AutonomousAgentRun,
  AutonomousAgentRunRequest,
  CaseGraphResponse,
  AssetDetail,
  AssetListResponse,
  AssetVulnerability,
  AuditResponse,
  CandidateItem,
  CandidateListResponse,
  CandidateRecalculationHistoryResponse,
  CandidateRecalculationResponse,
  CandidateWorkloadResponse,
  CapabilityCheckResponse,
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
  LiveRunEvent,
  ModelTrustResponse,
  PatchDetail,
  ProvenanceResponse,
  Recipe,
  RecipeDiffResult,
  RecipeLintResult,
  ReviewQueueResponse,
  RecipeListResponse,
  RunDetailResponse,
  RunHealthResponse,
  RunListResponse,
  SimulationResponse,
  SupplyChainOverviewResponse,
  TemplateListResponse,
  TenantListResponse,
  TenantOnboardResponse,
  V3AIProviderListResponse,
  V3AISessionListResponse,
  V3AnalysisCaseListResponse,
  V3DefangListResponse,
  V3FindingListResponse,
  V3IndicatorListResponse,
  V3PolicyListResponse,
  V3PreventionListResponse,
  V3ReportListResponse,
  V3SandboxProfileListResponse,
  V3SpecimenListResponse,
  V3SpecimenRevisionListResponse,
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

function streamUrl(path: string, params?: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  Object.entries(params ?? {}).forEach(([key, value]) => {
    if (value !== undefined && value !== "") {
      search.set(key, String(value));
    }
  });
  const query = search.toString();
  return `${API_BASE}${path}${query ? `?${query}` : ""}`;
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
  getCandidateRecalculationHistory: (limit = 20) =>
    fetchTenantJson<CandidateRecalculationHistoryResponse>("/api/candidates/recalculate/history", { limit }),
  recalculateCandidates: async (payload: Record<string, unknown>) =>
    fetchJson<CandidateRecalculationResponse>("/api/candidates/recalculate", {
      method: "POST",
      body: JSON.stringify(await withActiveTenant(payload)),
    }),
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
  streamRunEvents: (runId: number, handlers: { onEvent: (event: LiveRunEvent) => void; onError?: () => void }) => {
    const source = new EventSource(streamUrl(`/api/v4/runs/${runId}/events`));
    source.addEventListener("run_event", (event) => {
      handlers.onEvent(JSON.parse((event as MessageEvent).data) as LiveRunEvent);
    });
    source.onerror = () => {
      handlers.onError?.();
    };
    return source;
  },
  getReviewQueue: (params?: Record<string, string | number | boolean | undefined>) =>
    fetchTenantJson<ReviewQueueResponse>("/api/review-queue", params),

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
  reviewDisclosureBundle: async (payload: Record<string, unknown>) =>
    fetchJson<DisclosureBundleRecord>("/api/disclosures/review", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),

  listAuthorizations: (params?: Record<string, string | number | boolean | undefined>) =>
    fetchJson<AuthorizationListResponse>(streamUrl("/api/v4/authorization", params)),
  requestAuthorization: async (payload: Record<string, unknown>) =>
    fetchJson<AuthorizationArtifact>("/api/v4/authorization/request", { method: "POST", body: JSON.stringify(payload) }),
  revokeAuthorization: async (artifactId: string, payload: Record<string, unknown>) =>
    fetchJson<{ artifact_id: string; revoked: boolean }>(`/api/v4/authorization/${artifactId}/revoke`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  approveAuthorization: async (artifactId: string, payload: Record<string, unknown>) =>
    fetchJson<AuthorizationArtifact & { approval_status?: string }>(`/api/v4/authorization/${artifactId}/approve`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getAuthorizationChainRoot: () => fetchJson<AuthorizationChainRootResponse>("/api/v4/authorization/chain/root"),
  verifyAuthorizationChain: () => fetchJson<AuthorizationChainVerifyResponse>("/api/v4/authorization/chain/verify"),
  checkCapability: (capability: string, scope: Record<string, unknown> = {}, actor = "ui") =>
    fetchJson<CapabilityCheckResponse>(
      streamUrl("/api/v4/capability/check", { capability, scope: JSON.stringify(scope), actor }),
    ),
  getAttackCoverage: (params?: Record<string, string | number | boolean | undefined>) =>
    fetchTenantJson<AttackCoverageResponse>("/api/v4/attack/coverage", params),
  getAttackTechniqueFindings: (techniqueId: string) =>
    fetchTenantJson<AttackTechniqueFindingsResponse>(`/api/v4/attack/technique/${encodeURIComponent(techniqueId)}`),
  getCaseGraph: (caseId: number, depth = 2) =>
    fetchTenantJson<CaseGraphResponse>(`/api/v4/cases/${caseId}/graph`, { depth }),
  runAutonomousAgent: async (payload: AutonomousAgentRunRequest) =>
    fetchJson<AutonomousAgentRun>("/api/v4/autonomous/run", {
      method: "POST",
      body: JSON.stringify(await withActiveTenant(payload as Record<string, unknown>)),
    }),
  listAutonomousRuns: (params?: Record<string, string | number | boolean | undefined>) =>
    fetchTenantJson<{ items: AutonomousAgentRun[]; count: number }>("/api/v4/autonomous/runs", params),

  listSpecimens: () => fetchTenantJson<V3SpecimenListResponse>("/api/specimens"),
  createSpecimen: async (payload: Record<string, unknown>) =>
    fetchJson("/api/specimens", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  listSpecimenRevisions: (specimenId?: number) =>
    fetchTenantJson<V3SpecimenRevisionListResponse>("/api/specimen-revisions", specimenId ? { specimen_id: specimenId } : undefined),
  createSpecimenRevision: async (payload: Record<string, unknown>) =>
    fetchJson("/api/specimen-revisions", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),

  listAnalysisCases: () => fetchTenantJson<V3AnalysisCaseListResponse>("/api/analysis-cases"),
  getAnalysisCase: async (caseId: number) => fetchJson(await tenantPath(`/api/analysis-cases/${caseId}`)),
  createAnalysisCase: async (payload: Record<string, unknown>) =>
    fetchJson("/api/analysis-cases", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),

  listSandboxProfiles: () => fetchTenantJson<V3SandboxProfileListResponse>("/api/sandbox-profiles"),
  createSandboxProfile: async (payload: Record<string, unknown>) =>
    fetchJson("/api/sandbox-profiles", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),

  listFindings: (analysisCaseId?: number) =>
    fetchTenantJson<V3FindingListResponse>("/api/findings", analysisCaseId ? { analysis_case_id: analysisCaseId } : undefined),
  createFinding: async (payload: Record<string, unknown>) =>
    fetchJson("/api/findings", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  reviewFinding: async (payload: Record<string, unknown>) =>
    fetchJson("/api/findings/review", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),

  listIndicators: (analysisCaseId?: number) =>
    fetchTenantJson<V3IndicatorListResponse>("/api/indicators", analysisCaseId ? { analysis_case_id: analysisCaseId } : undefined),
  createIndicator: async (payload: Record<string, unknown>) =>
    fetchJson("/api/indicators", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),

  listPrevention: (analysisCaseId?: number) =>
    fetchTenantJson<V3PreventionListResponse>("/api/prevention", analysisCaseId ? { analysis_case_id: analysisCaseId } : undefined),
  createPrevention: async (payload: Record<string, unknown>) =>
    fetchJson("/api/prevention", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  reviewPrevention: async (payload: Record<string, unknown>) =>
    fetchJson("/api/prevention/review", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),

  listDefang: (analysisCaseId?: number) =>
    fetchTenantJson<V3DefangListResponse>("/api/defang", analysisCaseId ? { analysis_case_id: analysisCaseId } : undefined),
  createDefang: async (payload: Record<string, unknown>) =>
    fetchJson("/api/defang", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  reviewDefang: async (payload: Record<string, unknown>) =>
    fetchJson("/api/defang/review", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),

  listReports: (analysisCaseId?: number) =>
    fetchTenantJson<V3ReportListResponse>("/api/reports", analysisCaseId ? { analysis_case_id: analysisCaseId } : undefined),
  createReport: async (payload: Record<string, unknown>) =>
    fetchJson("/api/reports", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  reviewReport: async (payload: Record<string, unknown>) =>
    fetchJson("/api/reports/review", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  exportReport: async (reportId: number) =>
    fetchJson(await tenantPath(`/api/reports/${reportId}/export`), { method: "POST" }),

  listAIProviders: () => fetchTenantJson<V3AIProviderListResponse>("/api/ai/providers"),
  listAISessions: (analysisCaseId?: number) =>
    fetchTenantJson<V3AISessionListResponse>("/api/ai/sessions", analysisCaseId ? { analysis_case_id: analysisCaseId } : undefined),
  createAISession: async (payload: Record<string, unknown>) =>
    fetchJson("/api/ai/sessions", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
  reviewAISession: async (payload: Record<string, unknown>) =>
    fetchJson("/api/ai/sessions/review", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),

  listPolicies: () => fetchTenantJson<V3PolicyListResponse>("/api/policy"),
  createPolicy: async (payload: Record<string, unknown>) =>
    fetchJson("/api/policy", { method: "POST", body: JSON.stringify(await withActiveTenant(payload)) }),
};
