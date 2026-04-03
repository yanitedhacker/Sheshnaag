import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { CopilotPanel } from "../components/CopilotPanel";
import { SignalPills } from "../components/SignalPills";
import type { WorkbenchAction } from "../types";

export function WorkbenchPage() {
  const dashboard = useQuery({ queryKey: ["dashboard"], queryFn: api.getDashboard });
  const workbench = useQuery({ queryKey: ["workbench"], queryFn: api.getWorkbench });
  const [selectedActionId, setSelectedActionId] = useState<string | null>(null);

  const actions = workbench.data?.actions ?? [];
  const selected = useMemo<WorkbenchAction | undefined>(() => {
    if (!actions.length) return undefined;
    return actions.find((action) => action.action_id === selectedActionId) ?? actions[0];
  }, [actions, selectedActionId]);

  if (dashboard.isLoading || workbench.isLoading) {
    return <section className="panel">Loading workbench...</section>;
  }

  if (dashboard.error || workbench.error) {
    return <section className="panel">Unable to load the v2 workbench right now.</section>;
  }

  return (
    <>
      <section className="page-hero panel">
        <div>
          <p className="eyebrow">Standout View</p>
          <h3>Exposure-aware remediation workbench</h3>
          <p className="muted">
            Prioritized actions blend exploit likelihood, KEV/EPSS enrichment, public exposure, crown-jewel context,
            and persisted attack paths.
          </p>
        </div>
        <div className="hero-stats">
          <div>
            <div className="score">{dashboard.data?.workbench.summary.top_actionable_risk_score.toFixed(1)}</div>
            <div className="muted">Top actionable risk</div>
          </div>
        </div>
      </section>

      <section className="metric-grid">
        <article className="metric-card">
          <div className="metric-value">{dashboard.data?.organization_summary.total_assets}</div>
          <div className="metric-label">Demo assets</div>
        </article>
        <article className="metric-card">
          <div className="metric-value">{dashboard.data?.workbench.summary.exposed_assets}</div>
          <div className="metric-label">Exposed assets</div>
        </article>
        <article className="metric-card">
          <div className="metric-value">{dashboard.data?.organization_summary.total_open_vulnerabilities}</div>
          <div className="metric-label">Open vulnerabilities</div>
        </article>
        <article className="metric-card">
          <div className="metric-value">{dashboard.data?.attack_paths.length}</div>
          <div className="metric-label">Attack paths previewed</div>
        </article>
      </section>

      <section className="page-grid">
        <section className="list-card">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Ranked Actions</p>
              <h3>What to patch first</h3>
            </div>
            <div className="button-row">
              <Link className="ghost-button" to="/simulator">
                Run Simulation
              </Link>
              <Link className="ghost-button" to="/operations">
                Governance
              </Link>
            </div>
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
                  <p className="eyebrow">Why This Matters</p>
                  <h3>{selected.title}</h3>
                </div>
                <div className="score">{selected.actionable_risk_score.toFixed(0)}</div>
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
                    <strong>{item.title}</strong>
                    <p className="muted">{item.summary}</p>
                  </article>
                ))}
              </div>

              {selected.attack_path_preview && selected.attack_path_preview.length > 0 && (
                <div className="panel">
                  <p className="eyebrow">Path Preview</p>
                  {selected.attack_path_preview.map((path) => (
                    <div key={path} className="path-card">
                      {path}
                    </div>
                  ))}
                </div>
              )}

              {(selected.approval_summary || selected.feedback_summary) && (
                <div className="panel">
                  <p className="eyebrow">Governance Context</p>
                  <div className="action-list">
                    {selected.approval_summary && (
                      <article className="asset-card">
                        <strong>{selected.approval_summary.approval_state}</strong>
                        <p className="muted">
                          {selected.approval_summary.note || `Window ${selected.approval_summary.maintenance_window || "TBD"}`}
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
                {selected.citations.map((citation) => (
                  <a key={citation.url} href={citation.url} target="_blank" rel="noreferrer">
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

      <CopilotPanel />
    </>
  );
}
