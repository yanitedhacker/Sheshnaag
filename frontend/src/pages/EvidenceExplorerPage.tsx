import { useEffect, useState } from "react";
import { api } from "../api";
import type { EvidenceListResponse, RunDetailResponse, RunSummary } from "../types";

export function EvidenceExplorerPage() {
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [runId, setRunId] = useState<number | null>(null);
  const [detail, setDetail] = useState<RunDetailResponse | null>(null);
  const [evidence, setEvidence] = useState<EvidenceListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listRuns()
      .then((data) => {
        setRuns(data.items);
        setRunId(data.items[0]?.id ?? null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load runs."));
  }, []);

  useEffect(() => {
    if (!runId) {
      return;
    }
    Promise.all([api.getRun(runId), api.listEvidence(runId)])
      .then(([runDetail, evidenceList]) => {
        setDetail(runDetail);
        setEvidence(evidenceList);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load evidence."));
  }, [runId]);

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Evidence Explorer</p>
          <h1>Timeline-backed run evidence</h1>
          <p className="page-copy">Inspect collector output, runtime findings, and evidence storage metadata by validation run.</p>
        </div>
      </div>

      {error ? <div className="panel error-panel">{error}</div> : null}

      <section className="panel">
        <div className="toolbar">
          <select value={runId ?? ""} onChange={(event) => setRunId(Number(event.target.value))}>
            {runs.map((run) => (
              <option value={run.id} key={run.id}>
                Run #{run.id} · {run.state}
              </option>
            ))}
          </select>
          <span className="status-pill">{detail?.runtime_findings_summary.count ?? 0} findings</span>
        </div>
      </section>

      <div className="panel-grid">
        <section className="panel">
          <div className="panel-header">
            <h2>Evidence timeline</h2>
            <span>{detail?.evidence_timeline.items.length ?? 0} points</span>
          </div>
          <div className="stack-list">
            {(detail?.evidence_timeline.items ?? []).map((item) => (
              <article className="line-card" key={item.evidence_id}>
                <div>
                  <strong>{item.title}</strong>
                  <p>{item.collector_name ?? item.artifact_kind}</p>
                </div>
                <span>{item.timestamp ? new Date(item.timestamp).toLocaleString() : "n/a"}</span>
              </article>
            ))}
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2>Collected artifacts</h2>
            <span>{evidence?.count ?? 0} rows</span>
          </div>
          <div className="stack-list">
            {(evidence?.items ?? []).map((item) => (
              <article className="line-card" key={item.id}>
                <div>
                  <strong>{item.title}</strong>
                  <p>{item.summary ?? item.artifact_kind}</p>
                </div>
                <span>{item.collector_name ?? item.artifact_kind}</span>
              </article>
            ))}
            {!evidence?.items.length ? <div className="empty-panel">No evidence has been captured for this run yet.</div> : null}
          </div>
        </section>
      </div>

      {detail ? (
        <section className="panel">
          <div className="panel-header">
            <h2>Collector readiness and findings</h2>
            <span>{detail.collector_capabilities.length} collectors</span>
          </div>
          <div className="stack-list">
            {detail.collector_capabilities.map((collector) => (
              <article className="line-card" key={collector.collector_name}>
                <div>
                  <strong>{collector.collector_name}</strong>
                  <p>{collector.reason ?? collector.tier}</p>
                </div>
                <span>{collector.status}</span>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      <section className="panel">
        <div className="panel-header">
          <h2>Evidence detail panes</h2>
          <span>{evidence?.items.length ?? 0} loaded</span>
        </div>
        <div className="stack-list">
          {(evidence?.items ?? []).map((item) => {
            const payload = item.payload ?? {};
            const findings = Array.isArray(payload.findings) ? payload.findings : [];
            const processes = Array.isArray(payload.processes) ? payload.processes : [];
            const sources = Array.isArray(payload.sources) ? payload.sources : [];
            const queryResults = Array.isArray(payload.query_results) ? payload.query_results : [];
            return (
              <article className="line-card" key={`detail-${item.id}`}>
                <div>
                  <strong>{item.artifact_kind}</strong>
                  <p>{item.title}</p>
                  {processes.length ? <p>Process tree rows: {processes.length}</p> : null}
                  {sources.length ? <p>Service log sources: {sources.length}</p> : null}
                  {queryResults.length ? <p>osquery result sets: {queryResults.length}</p> : null}
                  {findings.length ? <p>Runtime findings: {findings.length}</p> : null}
                  {"raw_socket_summary" in payload ? <p>Network summary captured.</p> : null}
                  {"pcap_base64_preview" in payload ? <p>PCAP preview captured.</p> : null}
                </div>
                <span>{item.reviewed_state}</span>
              </article>
            );
          })}
        </div>
      </section>
    </section>
  );
}
