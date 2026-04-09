import { useEffect, useState } from "react";
import { api } from "../api";
import type { CandidateItem, CandidateWorkloadResponse, IntelOverviewResponse } from "../types";

export function CandidateQueuePage() {
  const [items, setItems] = useState<CandidateItem[]>([]);
  const [selected, setSelected] = useState<CandidateItem | null>(null);
  const [overview, setOverview] = useState<IntelOverviewResponse | null>(null);
  const [workload, setWorkload] = useState<CandidateWorkloadResponse | null>(null);
  const [status, setStatus] = useState("");
  const [assignee, setAssignee] = useState("Demo Analyst");
  const [reason, setReason] = useState("");
  const [mergeIntoId, setMergeIntoId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function loadQueue(nextStatus = status) {
    const [candidateList, intel, workloadSummary] = await Promise.all([
      api.getCandidates({ status: nextStatus || undefined, limit: 20 }),
      api.getIntelOverview(),
      api.getCandidateWorkload(),
    ]);
    setItems(candidateList.items);
    setSelected((current) => candidateList.items.find((item) => item.id === current?.id) ?? candidateList.items[0] ?? null);
    setOverview(intel);
    setWorkload(workloadSummary);
  }

  useEffect(() => {
    loadQueue().catch((err) => setError(err instanceof Error ? err.message : "Failed to load candidates."));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function runAction(action: "assign" | "defer" | "reject" | "restore" | "archive" | "merge") {
    if (!selected) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      if (action === "assign") {
        await api.assignCandidate(selected.id, { analyst_name: assignee, assigned_by: assignee });
      } else if (action === "defer") {
        await api.deferCandidate(selected.id, { reason, changed_by: assignee });
      } else if (action === "reject") {
        await api.rejectCandidate(selected.id, { reason, changed_by: assignee });
      } else if (action === "restore") {
        await api.restoreCandidate(selected.id, { reason, changed_by: assignee });
      } else if (action === "archive") {
        await api.archiveCandidate(selected.id, { reason, changed_by: assignee });
      } else if (action === "merge") {
        await api.mergeCandidateDuplicate(selected.id, { merge_into_id: Number(mergeIntoId), merged_by: assignee });
      }
      await loadQueue();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Candidate action failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro split-intro">
        <div>
          <p className="eyebrow">Candidate Queue</p>
          <h1>Triage the next validation target</h1>
          <p className="page-copy">Use explainability, freshness, and workload views to move candidates through review.</p>
        </div>
        <div className="mini-metrics">
          <span className="status-pill">{workload?.total_active ?? 0} active</span>
          <span className="status-pill">{workload?.unassigned ?? 0} unassigned</span>
        </div>
      </div>

      {error ? <div className="panel error-panel">{error}</div> : null}

      <section className="panel">
        <div className="panel-header">
          <h2>Freshness signals</h2>
          <span>{overview?.sources.length ?? 0} feeds</span>
        </div>
        <div className="chips-row">
          {(overview?.sources ?? []).map((source) => (
            <span className={`status-pill ${source.is_stale ? "status-danger" : "status-good"}`} key={source.feed_key}>
              {source.display_name}: {source.is_stale ? "stale" : "fresh"}
            </span>
          ))}
        </div>
      </section>

      <div className="panel-grid candidate-grid">
        <section className="panel">
          <div className="toolbar">
            <select value={status} onChange={(event) => setStatus(event.target.value)}>
              <option value="">All statuses</option>
              <option value="queued">Queued</option>
              <option value="in_review">In review</option>
              <option value="deferred">Deferred</option>
              <option value="rejected">Rejected</option>
              <option value="archived">Archived</option>
            </select>
            <button className="primary-button" onClick={() => loadQueue(status).catch(() => null)}>Apply filter</button>
          </div>
          <div className="data-table">
            {items.map((item) => (
              <button
                type="button"
                key={item.id}
                className={`table-row-button${selected?.id === item.id ? " is-selected" : ""}`}
                onClick={() => setSelected(item)}
              >
                <strong>{item.cve_id ?? `Candidate ${item.id}`}</strong>
                <span>{item.package_name ?? item.product_name ?? "Unknown package"}</span>
                <span>{item.candidate_score.toFixed(1)}</span>
                <span>{item.status}</span>
              </button>
            ))}
            {!items.length ? <div className="empty-panel">No candidates match the current filter.</div> : null}
          </div>
        </section>

        <section className="panel detail-panel">
          <div className="panel-header">
            <h2>{selected?.title ?? "Select a candidate"}</h2>
            <span className="status-pill">{selected?.status ?? "idle"}</span>
          </div>
          {selected ? (
            <>
              <p className="page-copy">{selected.summary}</p>
              <div className="stat-inline-grid">
                <article><span>Score</span><strong>{selected.candidate_score.toFixed(1)}</strong></article>
                <article><span>Patch</span><strong>{selected.patch_available ? "available" : "missing"}</strong></article>
                <article><span>Assignee</span><strong>{selected.assigned_to ?? "unassigned"}</strong></article>
              </div>
              <div className="stack-list">
                {selected.explainability.factor_details.map((factor) => (
                  <article className="line-card" key={factor.key}>
                    <div>
                      <strong>{factor.key}</strong>
                      <p>{factor.reason}</p>
                    </div>
                    <span>{factor.weighted.toFixed(2)}</span>
                  </article>
                ))}
              </div>
              <div className="toolbar">
                <input value={assignee} onChange={(event) => setAssignee(event.target.value)} placeholder="Reviewer / analyst" />
                <button className="ghost-button" disabled={busy} onClick={() => runAction("assign")}>Assign</button>
              </div>
              <textarea value={reason} onChange={(event) => setReason(event.target.value)} rows={3} placeholder="Reason for status change" />
              <div className="button-row">
                <button className="ghost-button" disabled={busy} onClick={() => runAction("defer")}>Defer</button>
                <button className="ghost-button" disabled={busy} onClick={() => runAction("reject")}>Reject</button>
                <button className="ghost-button" disabled={busy} onClick={() => runAction("restore")}>Restore</button>
                <button className="ghost-button" disabled={busy} onClick={() => runAction("archive")}>Archive</button>
              </div>
              <div className="toolbar">
                <input value={mergeIntoId} onChange={(event) => setMergeIntoId(event.target.value)} placeholder="Merge into candidate ID" />
                <button className="primary-button" disabled={busy || !mergeIntoId} onClick={() => runAction("merge")}>Merge duplicate</button>
              </div>
            </>
          ) : (
            <div className="empty-panel">Pick a candidate to inspect explainability and triage controls.</div>
          )}
        </section>
      </div>
    </section>
  );
}
