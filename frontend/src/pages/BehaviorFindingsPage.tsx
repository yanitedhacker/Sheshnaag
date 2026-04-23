import { useEffect, useState } from "react";
import { api } from "../api";
import type { V3AnalysisCaseRecord, V3FindingRecord } from "../types";

export function BehaviorFindingsPage() {
  const [cases, setCases] = useState<V3AnalysisCaseRecord[]>([]);
  const [items, setItems] = useState<V3FindingRecord[]>([]);
  const [analysisCaseId, setAnalysisCaseId] = useState<number>(0);
  const [findingType, setFindingType] = useState("suspicious_dns");
  const [title, setTitle] = useState("Beaconing to parked domain");
  const [severity, setSeverity] = useState("high");
  const [confidence, setConfidence] = useState(0.82);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const [caseList, findingList] = await Promise.all([api.listAnalysisCases(), api.listFindings()]);
    setCases(caseList.items);
    setItems(findingList.items);
    if (!analysisCaseId && caseList.items[0]) {
      setAnalysisCaseId(caseList.items[0].id);
    }
  }

  useEffect(() => {
    load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load findings."));
  }, []);

  async function createFinding() {
    if (!analysisCaseId) {
      return;
    }
    try {
      await api.createFinding({
        analysis_case_id: analysisCaseId,
        finding_type: findingType,
        title,
        severity,
        confidence,
        payload: { review_sensitivity: { operator_attention: true } },
      });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Finding creation failed.");
    }
  }

  async function reviewFinding(findingId: number, decision: string) {
    try {
      await api.reviewFinding({ finding_id: findingId, reviewer_name: "Lead Reviewer", decision });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Finding review failed.");
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Behavior Findings</p>
          <h1>Normalized observed behavior</h1>
          <p className="page-copy">Record persistence attempts, DNS beacons, staged payload fetches, and other reviewable findings against each analysis case.</p>
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
          <input value={findingType} onChange={(event) => setFindingType(event.target.value)} placeholder="Finding type" />
          <input value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Title" />
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <input value={String(confidence)} onChange={(event) => setConfidence(Number(event.target.value))} placeholder="Confidence" />
          <button className="primary-button" onClick={() => void createFinding()}>
            Add finding
          </button>
        </div>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>Findings</h2>
          <span>{items.length}</span>
        </div>
        <div className="stack-list">
          {items.map((item) => (
            <article className="line-card stacked-card" key={item.id}>
              <div>
                <strong>{item.title}</strong>
                <p>
                  {item.finding_type} · {item.severity} · {Math.round(item.confidence * 100)}%
                </p>
                <p className="muted">Case #{item.analysis_case_id} · {item.status}</p>
              </div>
              <div className="button-row">
                <button className="ghost-button" onClick={() => void reviewFinding(item.id, "under_review")}>Review</button>
                <button className="ghost-button" onClick={() => void reviewFinding(item.id, "approved")}>Approve</button>
              </div>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
}
