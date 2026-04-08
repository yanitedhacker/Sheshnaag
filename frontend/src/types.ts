export type Citation = {
  label: string;
  url: string;
};

export type EvidenceItem = {
  kind: string;
  title: string;
  summary: string;
  severity: string;
};

export type EntityRef = {
  type: string;
  id: string;
  label: string;
};

export type WorkbenchAction = {
  action_id: string;
  action_type: string;
  title: string;
  entity_refs: EntityRef[];
  actionable_risk_score: number;
  recommended_action: string;
  confidence: number;
  confidence_band: { lower: number; upper: number };
  attack_path_count: number;
  attack_path_preview?: string[];
  expected_risk_reduction: number;
  operational_cost_score: number;
  justification: string[];
  approval_state: string;
  approval_summary?: {
    approval_type: string;
    approval_state: string;
    maintenance_window?: string | null;
    decided_by?: string | null;
    decided_at?: string | null;
    note?: string | null;
  } | null;
  feedback_summary?: {
    feedback_type: string;
    note?: string | null;
    created_at?: string | null;
  } | null;
  signals: {
    kev: boolean;
    epss: number;
    public_exposure: boolean;
    crown_jewel: boolean;
    exploit_available: boolean;
    vex_status: string;
  };
  evidence: EvidenceItem[];
  citations: Citation[];
};

export type WorkbenchSummary = {
  tenant: { id: number; slug: string; name: string };
  generated_at: string;
  count: number;
  summary: {
    exposed_assets: number;
    crown_jewel_assets: number;
    top_actionable_risk_score: number;
  };
  actions: WorkbenchAction[];
};

export type GraphNode = {
  id: number;
  node_type: string;
  node_key: string;
  label: string;
  metadata: Record<string, unknown>;
};

export type GraphEdge = {
  id: number;
  from_node_id: number;
  to_node_id: number;
  edge_type: string;
  weight: number;
  metadata: Record<string, unknown>;
};

export type AttackPath = {
  score: number;
  node_ids: number[];
  labels: string[];
  edge_types: string[];
  summary: string;
};

export type GraphResponse = {
  tenant: { id: number; slug: string; name: string };
  nodes: GraphNode[];
  edges: GraphEdge[];
  paths: AttackPath[];
  cached: boolean;
};

export type DashboardResponse = {
  tenant: { id: number; slug: string; name: string };
  risk_summary: {
    total_cves_scored: number;
    risk_level_distribution: Record<string, number>;
    average_risk_score: number;
    average_exploit_probability: number;
    recent_critical_cves: number;
    cves_with_exploits: number;
    last_updated: string;
  };
  workbench: WorkbenchSummary;
  top_priorities: WorkbenchAction[];
  cve_statistics: {
    total_cves: number;
    severity_distribution: Record<string, number>;
    with_exploits: number;
    recent_7_days: number;
    last_updated: string;
  };
  trending_cves: Array<{
    id: number;
    cve_id: string;
    description: string | null;
    published_date: string | null;
    last_modified_date?: string | null;
    cvss_v3_score: number | null;
    attack_vector: string | null;
    exploit_available: boolean;
    risk?: {
      overall_score: number;
      risk_level: string;
      exploit_probability: number;
      priority_rank: number | null;
      explanation: string | null;
    };
  }>;
  attack_paths: AttackPath[];
  intel_summary: {
    kev_entries: number;
    epss_snapshots: number;
    attack_techniques: number;
    knowledge_documents: number;
    knowledge_chunks: number;
    graph_nodes: number;
    graph_edges: number;
  };
  showcase_highlights: string[];
  organization_summary: {
    total_assets: number;
    criticality_distribution: Record<string, number>;
    open_vulnerabilities_by_risk: Record<string, number>;
    total_open_vulnerabilities: number;
    most_vulnerable_assets: Array<{ id: number; name: string; criticality: string; vulnerability_count: number }>;
    last_updated: string;
  };
  model_trust: ModelTrustResponse;
  governance?: {
    approvals: ApprovalItem[];
    feedback: FeedbackItem[];
  };
};

export type AssetListResponse = {
  results: Array<{
    id: number;
    tenant_id: number | null;
    name: string;
    asset_type: string | null;
    environment: string | null;
    criticality: string;
    business_criticality: string | null;
    is_crown_jewel: boolean;
    open_vulnerabilities: number;
  }>;
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
};

export type AssetDetail = {
  id: number;
  tenant_id: number | null;
  name: string;
  asset_type: string | null;
  hostname: string | null;
  ip_address: string | null;
  environment: string | null;
  criticality: string;
  business_criticality: string | null;
  is_crown_jewel: boolean;
  installed_software: Array<{ vendor: string; product: string; version?: string }>;
  owner: string | null;
  total_open_vulnerabilities: number;
  vulnerability_summary: Record<string, number>;
};

export type AssetVulnerability = {
  vulnerability_id: number;
  cve_id: string;
  description: string | null;
  cvss_score: number | null;
  status: string;
  detected_date: string | null;
  risk_level: string | null;
  overall_risk_score: number | null;
  exploit_available: boolean;
};

export type CveDetail = {
  id: number;
  cve_id: string;
  description: string | null;
  published_date: string | null;
  last_modified_date?: string | null;
  cvss_v3_score: number | null;
  attack_vector: string | null;
  exploit_available: boolean;
  affected_products?: Array<{ vendor: string; product: string; version?: string }>;
  risk?: {
    overall_score: number;
    risk_level: string;
    exploit_probability: number;
    priority_rank: number | null;
    explanation: string | null;
    top_features?: Array<{ feature: string; contribution: number }>;
  };
  intel?: {
    kev?: {
      present: boolean;
      short_description?: string;
      known_ransomware_use?: string;
      source_url?: string;
    };
    epss?: {
      score: number;
      percentile: number;
      scored_at: string | null;
      source_url?: string;
    } | null;
    attack_techniques?: Array<{ external_id: string; name: string; tactic?: string; source_url?: string }>;
    knowledge_documents?: Array<{ title: string; document_type: string; source_label?: string; source_url?: string }>;
  };
};

export type PatchDetail = {
  patch: {
    patch_id: string;
    vendor: string;
    affected_software: string;
    requires_reboot: boolean;
    estimated_downtime_minutes: number | null;
    advisory_url?: string;
  };
  linked_cves: Array<{ cve_id: string; cvss_v3_score: number | null; exploit_available: boolean }>;
  asset_mappings: Array<{ asset_id: number; maintenance_window?: string; environment?: string; status?: string }>;
  approvals?: ApprovalItem[];
};

export type SimulationResponse = {
  simulation_id: number | null;
  summary: {
    selected_patch_ids: string[];
    windows_considered: number;
    actions_selected: number;
    expected_risk_reduction: number;
    parameters: Record<string, unknown>;
  };
  before: WorkbenchSummary;
  after: { actions: Array<WorkbenchAction & { selected_for_window: boolean; post_simulation_risk_score: number }> };
  schedule: {
    constraints: Array<Record<string, unknown>>;
    schedule: Array<{ window: string; patches: string[]; total_downtime: number; risk_reduction: number }>;
  };
};

export type CopilotResponse = {
  answer_markdown: string;
  citations: Citation[];
  supporting_entities: EntityRef[];
  confidence: number;
  cannot_answer_reason: string | null;
};

export type ModelTrustResponse = {
  model_version: string;
  generated_at: string;
  training_date?: string | null;
  calibration_curve: Array<{ predicted_probability_bucket: number; average_risk_score: number; sample_size: number }>;
  feature_importance: Array<{ feature: string; frequency: number }>;
  drift: {
    status: string;
    delta_vs_epss: number;
    average_model_exploit_probability: number;
    average_epss_score: number;
  };
  coverage: {
    recent_scores: number;
    latest_epss_samples: number;
    knowledge_chunks: number;
  };
  score_history: Array<{ created_at: string | null; overall_score: number; exploit_probability: number }>;
  analyst_feedback: {
    summary: Record<string, number>;
    recent_items: FeedbackItem[];
  };
  retrieval: {
    embedding_model: string;
    chunk_count: number;
    index_status: string;
  };
  baselines: {
    epss_average: number;
    model_average: number;
    comparison_window: number;
  };
  notes: string[];
};

export type FeedbackItem = {
  id: number;
  tenant_id: number;
  action_id: string;
  feedback_type: string;
  note?: string | null;
  metadata: Record<string, unknown>;
  created_at?: string | null;
};

export type ApprovalItem = {
  id: number;
  tenant_id: number;
  patch_id: string;
  action_id: string;
  approval_type: string;
  approval_state: string;
  maintenance_window?: string | null;
  decided_by?: string | null;
  note?: string | null;
  metadata: Record<string, unknown>;
  decided_at?: string | null;
};

export type AuditItem = {
  id: number;
  tenant_id: number;
  actor_user_id?: number | null;
  event_type: string;
  entity_type: string;
  entity_id: string;
  summary: string;
  details: Record<string, unknown>;
  previous_hash?: string | null;
  event_hash: string;
  created_at?: string | null;
};

export type ApprovalResponse = {
  tenant: { id: number; slug: string; name: string };
  items: ApprovalItem[];
};

export type FeedbackResponse = {
  tenant: { id: number; slug: string; name: string };
  summary: Record<string, number>;
  items: FeedbackItem[];
};

export type AuditResponse = {
  tenant: { id: number; slug: string; name: string };
  items: AuditItem[];
};

export type TenantWorkspace = {
  tenant_id: number;
  tenant_slug: string;
  tenant_name: string;
  role?: string | null;
  scopes: string[];
  is_demo?: boolean;
  is_read_only?: boolean;
};

export type TenantListResponse = {
  items: TenantWorkspace[];
};

export type AuthUser = {
  id: number;
  email: string;
  full_name?: string | null;
  is_active: boolean;
};

export type TenantOnboardResponse = {
  tenant: {
    id: number;
    slug: string;
    name: string;
    description?: string | null;
    is_demo: boolean;
    is_read_only: boolean;
  };
  user: AuthUser;
  memberships: TenantWorkspace[];
  token: {
    access_token: string;
    token_type: string;
    expires_in: number;
  };
};

export type ImportResponse = {
  tenant: { id: number; slug: string };
  components_processed?: number;
  components_created?: number;
  asset_links_created?: number;
  services_created?: number;
  dependencies_linked?: number;
  knowledge_documents_created?: number;
  vulnerabilities_processed?: number;
  statements_created?: number;
  statements_updated?: number;
};

export type WorkbenchSort = "risk" | "confidence" | "reduction";

export type SupplyChainSource = {
  id: string;
  name: string;
  category: string;
  status: string;
  coverage: string;
  detail: string;
  official_url: string;
  signal_count: number | null;
};

export type SupplyChainOverviewResponse = {
  tenant: { id: number; slug: string; name: string };
  generated_at: string;
  mission: {
    headline: string;
    summary: string;
  };
  source_catalog: SupplyChainSource[];
  attack_story: Array<{
    title: string;
    detail: string;
    signal: string;
  }>;
  ai_threats: Array<{
    title: string;
    summary: string;
    detection: string;
    defense: string;
  }>;
  defense_layers: Array<{
    title: string;
    detail: string;
  }>;
  platform_capabilities: string[];
};

export type RecipeRevision = {
  id: number;
  revision_number: number;
  approval_state: string;
  risk_level: string;
  requires_acknowledgement: boolean;
  approved_by: string | null;
  approved_at: string | null;
  content: Record<string, unknown>;
};

export type Recipe = {
  id: number;
  candidate_id: number | null;
  name: string;
  objective: string;
  provider: string;
  status: string;
  created_by: string;
  current_revision_number: number;
  created_at: string | null;
  updated_at: string | null;
  revisions?: RecipeRevision[];
};

export type RecipeListResponse = {
  items: Recipe[];
  count: number;
};

export type RecipeLintResult = {
  errors: string[];
  warnings: string[];
  has_blocking_errors: boolean;
};

export type RecipeDiffChange = {
  field: string;
  old_value: unknown;
  new_value: unknown;
  is_policy_relevant: boolean;
};

export type RecipeDiffResult = {
  changes: RecipeDiffChange[];
  policy_changes: RecipeDiffChange[];
  risk_level_changed: boolean;
  collector_changes: boolean;
  network_changes: boolean;
  human_readable: string;
};

export type RunSummary = {
  id: number;
  recipe_revision_id: number;
  candidate_id: number | null;
  provider: string;
  provider_run_ref: string | null;
  state: string;
  launch_mode: string;
  guest_image: string | null;
  image_digest: string | null;
  network_mode: string | null;
  workspace_path: string | null;
  requires_acknowledgement: boolean;
  acknowledged_by: string | null;
  started_at: string | null;
  ended_at: string | null;
  manifest: Record<string, unknown>;
  run_transcript: string | null;
};

export type RunListResponse = {
  count: number;
  items: RunSummary[];
};

export type RunHealthResponse = RunSummary & {
  health: string;
  timeline: Array<{
    event_type: string;
    level: string;
    message: string;
    payload: Record<string, unknown>;
    created_at: string | null;
  }>;
};

export type TemplateItem = {
  id: number;
  provider: string;
  name: string;
  distro: string;
  base_image: string;
  is_hardened: boolean;
  network_mode: string;
};

export type TemplateListResponse = {
  items: TemplateItem[];
  count: number;
};
