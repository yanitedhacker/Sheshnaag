import { useEffect, useState } from "react";
import { api } from "../api";
import type { ProvenanceResponse, RunSummary } from "../types";

export function ProvenanceCenterPage() {
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [runId, setRunId] = useState<number | null>(null);
  const [provenance, setProvenance] = useState<ProvenanceResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listRuns()
      .then((data) => {
        setRuns(data.items);
        const first = data.items[0]?.id ?? null;
        setRunId(first);
        if (first) {
          return api.getProvenance(first).then(setProvenance);
        }
        return undefined;
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load provenance."));
  }, []);

  useEffect(() => {
    if (!runId) {
      return;
    }
    api.getProvenance(runId)
      .then(setProvenance)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load provenance."));
  }, [runId]);

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Provenance Center</p>
          <h1>Hashes, signatures, and review chain</h1>
          <p className="page-copy">Trace a run from recipe revision through evidence, artifacts, and disclosure exports.</p>
        </div>
      </div>

      {error ? <div className="panel error-panel">{error}</div> : null}

      <section className="panel">
        <div className="toolbar">
          <select value={runId ?? ""} onChange={(event) => setRunId(Number(event.target.value))}>
            {runs.map((run) => (
              <option key={run.id} value={run.id}>
                Run #{run.id}
              </option>
            ))}
          </select>
          <span className="status-pill">{provenance?.count ?? 0} attestations</span>
        </div>
      </section>

      <div className="panel-grid">
        <section className="panel">
          <div className="panel-header">
            <h2>Manifest summary</h2>
          </div>
          <pre className="code-card">{JSON.stringify(provenance?.manifest_summary ?? {}, null, 2)}</pre>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2>Evidence linkage</h2>
          </div>
          <div className="stack-list">
            {(provenance?.evidence_linkage ?? []).map((row, index) => (
              <article className="line-card" key={`${row.id ?? index}`}>
                <div>
                  <strong>{String(row.artifact_kind ?? "artifact")}</strong>
                  <p>{String(row.collector_name ?? "collector")}</p>
                </div>
                <span>{String(row.sha256 ?? "").slice(0, 12)}</span>
              </article>
            ))}
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="panel-header">
          <h2>Review and export history</h2>
        </div>
        <div className="stack-list">
          {(provenance?.review_history ?? []).map((row, index) => (
            <article className="line-card" key={`review-${index}`}>
              <div>
                <strong>{String(row.decision ?? "review")}</strong>
                <p>{String(row.target_type ?? "target")} · {String(row.reviewer_name ?? "reviewer")}</p>
              </div>
              <span>{row.created_at ? new Date(String(row.created_at)).toLocaleString() : "n/a"}</span>
            </article>
          ))}
          {(provenance?.export_history ?? []).map((bundle) => (
            <article className="line-card" key={`bundle-${bundle.id}`}>
              <div>
                <strong>{bundle.title}</strong>
                <p>{bundle.bundle_type}</p>
              </div>
              <a className="ghost-button" href={bundle.download_url}>Download</a>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
}
