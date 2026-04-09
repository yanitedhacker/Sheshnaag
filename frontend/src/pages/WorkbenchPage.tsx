import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { CopilotPanel } from "../components/CopilotPanel";
import { SignalPills } from "../components/SignalPills";
import type { WorkbenchAction, WorkbenchSort } from "../types";

type ActionFilter = "all" | "kev" | "exposed" | "crown" | "pending";

export function WorkbenchPage() {
  const dashboard = useQuery({ queryKey: ["dashboard"], queryFn: api.getDashboard });
  const workbench = useQuery({ queryKey: ["workbench"], queryFn: api.getWorkbench });
  const [selectedActionId, setSelectedActionId] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<ActionFilter>("all");
  const [sortBy, setSortBy] = useState<WorkbenchSort>("risk");

  const actions = useMemo(() => {
    const base = workbench.data?.actions ?? [];
    const filtered = base.filter((action) => {
      if (activeFilter === "kev") return action.signals.kev;
      if (activeFilter === "exposed") return action.signals.public_exposure;
      if (activeFilter === "crown") return action.signals.crown_jewel;
      if (activeFilter === "pending") return action.approval_state !== "approved";
      return true;
    });

    const ranked = [...filtered];
    ranked.sort((left, right) => {
      if (sortBy === "confidence") {
        return right.confidence - left.confidence;
      }
      if (sortBy === "reduction") {
        return right.expected_risk_reduction - left.expected_risk_reduction;
      }
      return right.actionable_risk_score - left.actionable_risk_score;
    });
    return ranked;
  }, [activeFilter, sortBy, workbench.data?.actions]);

  const selected = useMemo<WorkbenchAction | undefined>(() => {
    if (!actions.length) return undefined;
    return actions.find((action) => action.action_id === selectedActionId) ?? actions[0];
  }, [actions, selectedActionId]);

  if (dashboard.isLoading || workbench.isLoading) {
    return <section className="panel">Loading workbench...</section>;
  }

  if (dashboard.error || workbench.error || !dashboard.data) {
    return <section className="panel">Unable to load the v2 workbench right now.</section>;
  }

  const filterOptions: Array<{ id: ActionFilter; label: string }> = [
    { id: "all", label: "All Actions" },
    { id: "kev", label: "KEV" },
    { id: "exposed", label: "Public Exposure" },
    { id: "crown", label: "Crown Jewels" },
    { id: "pending", label: "Pending Approval" },
  ];

  const topRiskLevel = Object.entries(dashboard.data.risk_summary.risk_level_distribution).sort(
    (left, right) => Number(right[1]) - Number(left[1]),
  )[0];

  const missionBrief = selected
    ? `${selected.title} is high priority because it combines ${selected.attack_path_count} reachable attack path${
        selected.attack_path_count === 1 ? "" : "s"
      }, ${selected.signals.kev ? "known exploitation signals" : "strong exploitability signals"}, and an expected ${
        Math.round(selected.expected_risk_reduction * 100)
      }% reduction if patched.`
    : "No action selected.";

  return (
    <>
      <section className="command-hero panel">
        <div>
          <p className="eyebrow">Command Center</p>
          <h3>Multi-source CVE prioritization with graph-aware remediation</h3>
          <p className="muted">
            Prioritized actions blend exploit likelihood, KEV and EPSS enrichment, public exposure, crown-jewel
            context, governance state, and persisted attack paths.
          </p>
          <div className="inline-meta">
            <span>{dashboard.data.tenant.name}</span>
            <span>{dashboard.data.risk_summary.total_cves_scored} scored CVEs</span>
            {topRiskLevel && <span>Largest risk bucket {topRiskLevel[0]}</span>}
          </div>
        </div>

        <div className="hero-scorecard">
          <div className="score">{dashboard.data.workbench.summary.top_actionable_risk_score.toFixed(1)}</div>
          <div className="muted">Highest actionable risk</div>
          <div className="hero-bar">
            <span style={{ width: `${Math.min(100, dashboard.data.risk_summary.average_risk_score)}%` }} />
          </div>
          <small className="muted">
            Average risk {dashboard.data.risk_summary.average_risk_score.toFixed(1)} across the current corpus
          </small>
        </div>
      </section>

      <section className="metric-grid command-metrics">
        <article className="metric-card">
          <div className="metric-value">{dashboard.data.organization_summary.total_assets}</div>
          <div className="metric-label">Demo assets</div>
        </article>
        <article className="metric-card">
          <div className="metric-value">{dashboard.data.workbench.summary.exposed_assets}</div>
          <div className="metric-label">Exposed assets</div>
        </article>
        <article className="metric-card">
          <div className="metric-value">{dashboard.data.organization_summary.total_open_vulnerabilities}</div>
          <div className="metric-label">Open vulnerabilities</div>
        </article>
        <article className="metric-card">
          <div className="metric-value">{dashboard.data.attack_paths.length}</div>
          <div className="metric-label">Attack paths previewed</div>
        </article>
      </section>

      <section className="intel-strip">
        <article className="intel-card">
          <p className="eyebrow">Intel Fusion</p>
          <strong>{dashboard.data.intel_summary.kev_entries} KEV entries</strong>
          <span>{dashboard.data.intel_summary.epss_snapshots} EPSS snapshots correlated into scoring.</span>
        </article>
        <article className="intel-card">
          <p className="eyebrow">Knowledge Base</p>
          <strong>{dashboard.data.intel_summary.knowledge_documents} source documents</strong>
          <span>{dashboard.data.intel_summary.knowledge_chunks} retrieval chunks available for citations.</span>
        </article>
        <article className="intel-card">
          <p className="eyebrow">Exposure Graph</p>
          <strong>{dashboard.data.intel_summary.graph_nodes} nodes</strong>
          <span>{dashboard.data.intel_summary.graph_edges} edges materialized for attack-path reasoning.</span>
        </article>
        <article className="intel-card">
          <p className="eyebrow">ATT&CK Mapping</p>
          <strong>{dashboard.data.intel_summary.attack_techniques} techniques</strong>
          <span>Adversary behavior mappings used in explanation and path analysis.</span>
        </article>
      </section>

      <section className="page-grid">
        <section className="list-card">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Ranked Actions</p>
              <h3>What to patch first, and why</h3>
            </div>
            <div className="button-row action-toolbar">
              <select value={sortBy} onChange={(event) => setSortBy(event.target.value as WorkbenchSort)}>
                <option value="risk">Sort by risk</option>
                <option value="confidence">Sort by confidence</option>
                <option value="reduction">Sort by reduction</option>
              </select>
              <Link className="ghost-button" to="/simulator">
                Run Simulation
              </Link>
              <Link className="ghost-button" to="/operations">
                Governance
              </Link>
            </div>
          </div>

          <div className="filter-row">
            {filterOptions.map((option) => (
              <button
                key={option.id}
                type="button"
                className={`filter-chip ${activeFilter === option.id ? "active" : ""}`}
                onClick={() => setActiveFilter(option.id)}
              >
                {option.label}
              </button>
            ))}
          </div>

          <div className="action-list">
            {actions.map((action) => (
              <article
                key={action.action_id}
                className={`action-card ${selected?.action_id === action.action_id ? "active" : ""}`}
                onClick={() => setSelectedActionId(action.action_id)}
              >
                <div className="list-row">
                  <div>
                    <strong>{action.title}</strong>
                    <p className="muted">{action.recommended_action}</p>
                  </div>
                  <div className="score">{action.actionable_risk_score.toFixed(0)}</div>
                </div>
                <div className="inline-meta">
                  <span>{action.attack_path_count} attack paths</span>
                  <span>{Math.round(action.expected_risk_reduction * 100)}% expected reduction</span>
                  <span>{Math.round(action.confidence * 100)}% confidence</span>
                </div>
                <SignalPills action={action} />
              </article>
            ))}
          </div>
        </section>

        <section className="detail-card">
          {selected ? (
            <>
              <div className="detail-header">
                <div>
                  <p className="eyebrow">Action Dossier</p>
                  <h3>{selected.title}</h3>
                </div>
                <div className="score">{selected.actionable_risk_score.toFixed(0)}</div>
              </div>

              <div className="mission-brief">
                <p className="eyebrow">Mission Brief</p>
                <p>{missionBrief}</p>
              </div>

              <div className="inline-meta">
                <span>Confidence band {selected.confidence_band.lower} - {selected.confidence_band.upper}</span>
                <span>Operational cost {selected.operational_cost_score.toFixed(2)}</span>
                <span>Approval {selected.approval_state}</span>
              </div>

              <SignalPills action={selected} />

              <div className="evidence-list">
                {selected.evidence.map((item) => (
                  <article key={`${item.kind}-${item.title}`} className="vuln-card">
                    <span
                      className={`pill ${
                        item.severity === "critical" ? "critical" : item.severity === "high" ? "high" : "neutral"
                      }`}
                    >
                      {item.kind}
                    </span>
                    <strong>{item.title}</strong>
                    <p className="muted">{item.summary}</p>
                  </article>
                ))}
              </div>

              {selected.attack_path_preview && selected.attack_path_preview.length > 0 && (
                <div className="panel inset">
                  <p className="eyebrow">Path Preview</p>
                  {selected.attack_path_preview.map((path) => (
                    <div key={path} className="path-card">
                      {path}
                    </div>
                  ))}
                </div>
              )}

              {(selected.approval_summary || selected.feedback_summary) && (
                <div className="panel inset">
                  <p className="eyebrow">Governance Context</p>
                  <div className="action-list">
                    {selected.approval_summary && (
                      <article className="asset-card">
                        <strong>{selected.approval_summary.approval_state}</strong>
                        <p className="muted">
                          {selected.approval_summary.note ||
                            `Window ${selected.approval_summary.maintenance_window || "TBD"}`}
                        </p>
                      </article>
                    )}
                    {selected.feedback_summary && (
                      <article className="asset-card">
                        <strong>{selected.feedback_summary.feedback_type}</strong>
                        <p className="muted">{selected.feedback_summary.note}</p>
                      </article>
                    )}
                  </div>
                </div>
              )}

              <div className="inline-meta">
                {selected.entity_refs
                  .filter((entity) => entity.type === "cve")
                  .map((entity) => (
                    <Link key={entity.id} className="ghost-button" to={`/cves/${entity.id}`}>
                      {entity.label}
                    </Link>
                  ))}
                <Link className="primary-button" to={`/patches/${selected.entity_refs[0]?.id}`}>
                  Open Patch Detail
                </Link>
              </div>

              <div className="citation-list">
                {selected.citations.filter((citation) => citation.url).map((citation) => (
                  <a key={citation.url ?? citation.label} href={citation.url ?? undefined} target="_blank" rel="noreferrer">
                    {citation.label}
                  </a>
                ))}
              </div>
            </>
          ) : (
            <p className="muted">No actions available.</p>
          )}
        </section>
      </section>

      <section className="showcase-grid">
        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Trending CVEs</p>
              <h3>Live priority candidates across the corpus</h3>
            </div>
            <span className="pill neutral">{dashboard.data.cve_statistics.recent_7_days} new in 7 days</span>
          </div>

          <div className="action-list">
            {dashboard.data.trending_cves.map((cve) => (
              <article key={cve.cve_id} className="asset-card">
                <div className="list-row">
                  <Link to={`/cves/${cve.cve_id}`}>
                    <strong>{cve.cve_id}</strong>
                  </Link>
                  <span className={`pill ${cve.exploit_available ? "high" : "neutral"}`}>
                    {cve.exploit_available ? "exploit seen" : "watch"}
                  </span>
                </div>
                <p className="muted">{cve.description}</p>
                <div className="inline-meta">
                  <span>CVSS {cve.cvss_v3_score ?? "n/a"}</span>
                  <span>Risk {cve.risk?.overall_score?.toFixed(0) ?? "n/a"}</span>
                  <span>Exploit prob {(cve.risk?.exploit_probability ?? 0).toFixed(2)}</span>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="stack-grid">
          <section className="panel">
            <p className="eyebrow">Most Exposed Assets</p>
            <div className="action-list">
              {dashboard.data.organization_summary.most_vulnerable_assets.slice(0, 4).map((asset) => (
                <article key={asset.id} className="asset-card">
                  <div className="list-row">
                    <strong>{asset.name}</strong>
                    <span className="pill neutral">{asset.criticality}</span>
                  </div>
                  <p className="muted">{asset.vulnerability_count} mapped vulnerabilities</p>
                </article>
              ))}
            </div>
          </section>

          <section className="panel">
            <p className="eyebrow">Why This Project Stands Out</p>
            <div className="action-list">
              {dashboard.data.showcase_highlights.map((item) => (
                <article key={item} className="asset-card">
                  {item}
                </article>
              ))}
            </div>
          </section>

          <section className="panel">
            <p className="eyebrow">Model Snapshot</p>
            <div className="inline-meta">
              <span>Version {dashboard.data.model_trust.model_version}</span>
              <span>Drift {dashboard.data.model_trust.drift.status}</span>
              <span>Delta vs EPSS {dashboard.data.model_trust.drift.delta_vs_epss.toFixed(3)}</span>
            </div>
            <div className="bar-track large">
              <div
                className="bar-fill"
                style={{ width: `${Math.min(100, dashboard.data.model_trust.coverage.recent_scores / 2)}%` }}
              />
            </div>
            <p className="muted">
              {dashboard.data.model_trust.coverage.recent_scores} recent scores,{" "}
              {dashboard.data.model_trust.coverage.knowledge_chunks} knowledge chunks, and{" "}
              {dashboard.data.model_trust.retrieval.index_status} retrieval index.
            </p>
          </section>
        </section>
      </section>

      <CopilotPanel />
    </>
  );
}
