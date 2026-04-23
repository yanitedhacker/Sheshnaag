import { useEffect, useState } from "react";
import { api } from "../api";
import type { V3AnalysisCaseRecord, V3DefangRecord } from "../types";

export function DefangQueuePage() {
  const [cases, setCases] = useState<V3AnalysisCaseRecord[]>([]);
  const [items, setItems] = useState<V3DefangRecord[]>([]);
  const [analysisCaseId, setAnalysisCaseId] = useState<number>(0);
  const [actionType, setActionType] = useState("url_neutralization");
  const [title, setTitle] = useState("Neutralize delivery URL");
  const [resultSummary, setResultSummary] = useState("Converted live URL into hxxps-safe notation for report sharing.");
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const [caseList, defangList] = await Promise.all([api.listAnalysisCases(), api.listDefang()]);
    setCases(caseList.items);
    setItems(defangList.items);
    if (!analysisCaseId && caseList.items[0]) {
      setAnalysisCaseId(caseList.items[0].id);
    }
  }

  useEffect(() => {
    load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load defang queue."));
  }, []);

  async function createAction() {
    if (!analysisCaseId) {
      return;
    }
    try {
      await api.createDefang({
        analysis_case_id: analysisCaseId,
        action_type: actionType,
        title,
        result_summary: resultSummary,
      });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Defang action creation failed.");
    }
  }

  async function reviewAction(actionId: number, decision: string) {
    try {
      await api.reviewDefang({ action_id: actionId, reviewer_name: "Lead Reviewer", decision });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Defang review failed.");
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Defang Queue</p>
          <h1>Track safe transformation work</h1>
          <p className="page-copy">Record URL neutralization, document sanitization, payload stripping, and other bounded safe-sharing operations.</p>
        </div>
      </div>
      {error ? <div className="panel error-panel">{error}</div> : null}
      <section className="panel">
        <div className="form-grid">
          <select value={analysisCaseId} onChange={(event) => setAnalysisCaseId(Number(event.target.value))}>
            {cases.map((item) => (
              <option key={item.id} value={item.id}>
                Case #{item.id} · {item.title}
              </option>
            ))}
          </select>
          <input value={actionType} onChange={(event) => setActionType(event.target.value)} placeholder="Action type" />
          <input value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Title" />
          <textarea value={resultSummary} onChange={(event) => setResultSummary(event.target.value)} placeholder="Result summary" rows={3} />
          <button className="primary-button" onClick={() => void createAction()}>
            Add defang action
          </button>
        </div>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>Queue</h2>
          <span>{items.length}</span>
        </div>
        <div className="stack-list">
          {items.map((item) => (
            <article className="line-card" key={item.id}>
              <div>
                <strong>{item.title}</strong>
                <p>
                  {item.action_type} · {item.status}
                </p>
                <p className="muted">{item.result_summary}</p>
              </div>
              <div className="button-row">
                <button className="ghost-button" onClick={() => void reviewAction(item.id, "under_review")}>Review</button>
                <button className="ghost-button" onClick={() => void reviewAction(item.id, "approved")}>Approve</button>
              </div>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
}
