import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { AttackCoverageResponse, AttackTechniqueFindingsResponse } from "../types";

export function AttackCoveragePage() {
  const [coverage, setCoverage] = useState<AttackCoverageResponse | null>(null);
  const [selected, setSelected] = useState<AttackTechniqueFindingsResponse | null>(null);
  const [since, setSince] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const data = await api.getAttackCoverage({ since: since || undefined });
    setCoverage(data);
  }

  useEffect(() => {
    load().catch((err) => setError(err instanceof Error ? err.message : "Failed to load ATT&CK coverage."));
  }, [since]);

  const techniqueRows = useMemo(() => {
    return Object.entries(coverage?.tactics ?? {}).flatMap(([tactic, bucket]) =>
      Object.entries(bucket.techniques).map(([techniqueId, technique]) => ({
        tactic,
        techniqueId,
        ...technique,
      })),
    );
  }, [coverage]);

  async function openTechnique(techniqueId: string) {
    try {
      setSelected(await api.getAttackTechniqueFindings(techniqueId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load technique findings.");
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro split-intro">
        <div>
          <p className="eyebrow">ATT&CK Coverage</p>
          <h1>Technique heatmap from mapped behavior findings</h1>
          <p className="page-copy">Track the tactics and techniques seen across malware-analysis runs and open the findings behind each cell.</p>
        </div>
        <input value={since} onChange={(event) => setSince(event.target.value)} placeholder="Since ISO timestamp" />
      </div>

      {error ? <div className="panel error-panel">{error}</div> : null}

      <section className="panel">
        <div className="panel-header">
          <h2>Technique coverage</h2>
          <span>{techniqueRows.length} techniques</span>
        </div>
        <div className="attack-grid">
          {techniqueRows.map((row) => (
            <button
              type="button"
              className="attack-cell"
              key={`${row.tactic}-${row.techniqueId}`}
              onClick={() => void openTechnique(row.techniqueId)}
              style={{ opacity: Math.min(1, 0.42 + row.count * 0.12) }}
            >
              <strong>{row.techniqueId}</strong>
              <span>{row.tactic}</span>
              <small>{row.count} findings · {Math.round(row.confidence_avg * 100)}%</small>
            </button>
          ))}
          {!techniqueRows.length ? <div className="empty-panel">No mapped ATT&CK techniques yet.</div> : null}
        </div>
      </section>

      {selected ? (
        <section className="panel">
          <div className="panel-header">
            <h2>{selected.technique_id}</h2>
            <span className="status-pill">{selected.tactic}</span>
          </div>
          <div className="stack-list">
            {selected.items.map((finding) => (
              <article className="line-card" key={finding.id}>
                <div>
                  <strong>{finding.title}</strong>
                  <p>{finding.finding_type} · case {finding.analysis_case_id} · run {finding.run_id ?? "n/a"}</p>
                </div>
                <span>{finding.severity} · {Math.round(finding.confidence * 100)}%</span>
              </article>
            ))}
          </div>
        </section>
      ) : null}
    </section>
  );
}
