import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { CandidateRecalculationRun, CandidateRecalculationResponse, ReviewQueueItem } from "../types";

export function ReviewQueuePage() {
  const [items, setItems] = useState<ReviewQueueItem[]>([]);
  const [history, setHistory] = useState<CandidateRecalculationRun[]>([]);
  const [entityType, setEntityType] = useState("");
  const [status, setStatus] = useState("");
  const [reviewer, setReviewer] = useState("");
  const [needsAttention, setNeedsAttention] = useState(true);
  const [requestedBy, setRequestedBy] = useState("Demo Analyst");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [lastRecalc, setLastRecalc] = useState<CandidateRecalculationResponse | null>(null);

  async function loadQueue() {
    const [queue, recalculationHistory] = await Promise.all([
      api.getReviewQueue({
        entity_type: entityType || undefined,
        status: status || undefined,
        reviewer: reviewer || undefined,
        needs_attention: needsAttention,
      }),
      api.getCandidateRecalculationHistory(8),
    ]);
    setItems(queue.items);
    setHistory(recalculationHistory.items);
  }

  useEffect(() => {
    loadQueue().catch((err) => setError(err instanceof Error ? err.message : "Failed to load review queue."));
  }, [entityType, status, reviewer, needsAttention]);

  async function runRecalculation(dryRun: boolean) {
    try {
      setBusy(true);
      setError(null);
      const result = await api.recalculateCandidates({
        requested_by: requestedBy,
        dry_run: dryRun,
        reason: dryRun ? "Operator dry-run validation from review queue" : "Operator-applied recalculation from review queue",
      });
      setLastRecalc(result);
      const recalculationHistory = await api.getCandidateRecalculationHistory(8);
      setHistory(recalculationHistory.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Candidate recalculation failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Review Queue</p>
          <h1>One queue for runs, evidence, artifacts, and bundles</h1>
          <p className="page-copy">Triage blockers across the operator console, then jump into the existing detail pages to take action.</p>
        </div>
      </div>

      {error ? <div className="panel error-panel">{error}</div> : null}

      <section className="panel">
        <div className="panel-header">
          <h2>Filters</h2>
          <span>{items.length} queue items</span>
        </div>
        <div className="form-grid">
          <select value={entityType} onChange={(event) => setEntityType(event.target.value)}>
            <option value="">All entities</option>
            <option value="run">Runs</option>
            <option value="evidence">Evidence</option>
            <option value="artifact">Artifacts</option>
            <option value="bundle">Bundles</option>
          </select>
          <input value={status} onChange={(event) => setStatus(event.target.value)} placeholder="Status or review state" />
          <input value={reviewer} onChange={(event) => setReviewer(event.target.value)} placeholder="Last reviewer" />
          <label className="checkbox-row">
            <input type="checkbox" checked={needsAttention} onChange={(event) => setNeedsAttention(event.target.checked)} />
            Needs attention now
          </label>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Queue</h2>
          <span>{items.filter((item) => item.needs_attention_now).length} urgent</span>
        </div>
        <div className="stack-list">
          {items.map((item) => (
            <article className="line-card" key={`${item.entity_type}-${item.entity_id}`}>
              <div>
                <strong>{item.title}</strong>
                <p>
                  {item.entity_type} #{item.entity_id}
                  {item.run_id ? ` · run #${item.run_id}` : ""}
                  {item.provider ? ` · ${item.provider}` : ""}
                </p>
                <p className="muted">
                  Status {item.status} · Review {item.review_state}
                  {item.last_reviewer ? ` · Last reviewer ${item.last_reviewer}` : ""}
                </p>
                {item.blocking_reasons.length ? (
                  <p className="muted">Blockers: {item.blocking_reasons.join(" · ")}</p>
                ) : (
                  <p className="muted">No active blockers recorded.</p>
                )}
              </div>
              <div className="stack-list" style={{ alignItems: "flex-end" }}>
                <span className={`status-pill${item.needs_attention_now ? " status-danger" : ""}`}>
                  {item.needs_attention_now ? "Attention" : "Ready"}
                </span>
                <Link className="ghost-button" to={item.route}>
                  Open detail page
                </Link>
              </div>
            </article>
          ))}
          {!items.length ? <div className="empty-panel">No review queue items matched the current filters.</div> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Candidate scoring backfill</h2>
          <span>{history.length} recorded runs</span>
        </div>
        <div className="form-grid">
          <input value={requestedBy} onChange={(event) => setRequestedBy(event.target.value)} placeholder="Requested by" />
          <button className="ghost-button" disabled={busy} onClick={() => void runRecalculation(true)}>
            {busy ? "Working..." : "Dry-run recalculation"}
          </button>
          <button className="primary-button" disabled={busy} onClick={() => void runRecalculation(false)}>
            {busy ? "Working..." : "Apply recalculation"}
          </button>
        </div>
        {lastRecalc ? (
          <article className="line-card">
            <div>
              <strong>Latest recalculation</strong>
              <p>
                {lastRecalc.changed_count} changed · {lastRecalc.unchanged_count} unchanged · average delta {lastRecalc.average_score_delta}
              </p>
              <p className="muted">Run #{lastRecalc.recalculation_run_id} · requested by {lastRecalc.requested_by}</p>
            </div>
          </article>
        ) : null}
        <div className="stack-list">
          {history.map((run) => (
            <article className="line-card" key={run.id}>
              <div>
                <strong>Recalculation #{run.id}</strong>
                <p>
                  {run.dry_run ? "dry run" : "applied"} · {run.requested_by}
                </p>
                <p className="muted">
                  Changed {String((run.summary as Record<string, unknown>).changed_count ?? 0)} of{" "}
                  {String((run.summary as Record<string, unknown>).total_candidates ?? 0)}
                </p>
              </div>
              <span>{run.created_at ? new Date(run.created_at).toLocaleString() : "n/a"}</span>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
}
