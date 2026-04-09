import { useEffect, useState } from "react";
import { api } from "../api";
import type { ArtifactListResponse, RunSummary } from "../types";

export function ArtifactForgePage() {
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [runId, setRunId] = useState<number | null>(null);
  const [artifacts, setArtifacts] = useState<ArtifactListResponse | null>(null);
  const [reviewer, setReviewer] = useState("Demo Reviewer");
  const [feedbackNote, setFeedbackNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function loadArtifacts(nextRunId: number) {
    const data = await api.listArtifacts(nextRunId);
    setArtifacts(data);
  }

  useEffect(() => {
    api.listRuns()
      .then((data) => {
        setRuns(data.items);
        const first = data.items[0]?.id ?? null;
        setRunId(first);
        if (first) {
          return loadArtifacts(first);
        }
        return undefined;
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load artifacts."));
  }, []);

  async function reviewArtifact(artifactFamily: "detection" | "mitigation", artifactId: number, decision: string) {
    try {
      await api.reviewArtifact({ artifact_family: artifactFamily, artifact_id: artifactId, decision, reviewer });
      if (runId) {
        await loadArtifacts(runId);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Artifact review failed.");
    }
  }

  async function sendFeedback(artifactFamily: "detection" | "mitigation", artifactId: number) {
    try {
      await api.addArtifactFeedback({
        artifact_family: artifactFamily,
        artifact_id: artifactId,
        reviewer,
        feedback_type: "false_positive",
        note: feedbackNote,
      });
      if (runId) {
        await loadArtifacts(runId);
      }
      setFeedbackNote("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Artifact feedback failed.");
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Artifact Forge</p>
          <h1>Evidence-backed defensive outputs</h1>
          <p className="page-copy">Review generated detections and mitigation guidance, then capture feedback before disclosure export.</p>
        </div>
      </div>

      {error ? <div className="panel error-panel">{error}</div> : null}

      <section className="panel">
        <div className="toolbar">
          <select value={runId ?? ""} onChange={(event) => {
            const nextId = Number(event.target.value);
            setRunId(nextId);
            loadArtifacts(nextId).catch(() => null);
          }}>
            {runs.map((run) => (
              <option value={run.id} key={run.id}>
                Run #{run.id}
              </option>
            ))}
          </select>
          <input value={reviewer} onChange={(event) => setReviewer(event.target.value)} placeholder="Reviewer name" />
        </div>
      </section>

      <div className="panel-grid">
        <section className="panel">
          <div className="panel-header">
            <h2>Detections</h2>
            <span>{artifacts?.summary.detection_count ?? 0} total</span>
          </div>
          <div className="stack-list">
            {(artifacts?.detections ?? []).map((item) => (
              <article className="line-card stacked-card" key={item.id}>
                <div>
                  <strong>{item.name}</strong>
                  <p>{item.artifact_type} · {item.status}</p>
                </div>
                <p className="muted">Review history: {item.review_history.length} · Feedback: {item.feedback.length}</p>
                {item.lineage?.supersedes_artifact_id ? (
                  <p className="muted">Supersedes artifact #{item.lineage.supersedes_artifact_id}</p>
                ) : null}
                {item.lineage?.correction_note ? <p className="muted">{item.lineage.correction_note}</p> : null}
                <pre className="code-card">{item.rule_body}</pre>
                <div className="button-row">
                  <button className="ghost-button" onClick={() => reviewArtifact("detection", item.id, "under_review")}>Send review</button>
                  <button className="ghost-button" onClick={() => reviewArtifact("detection", item.id, "changes_requested")}>Request changes</button>
                  <button className="ghost-button" onClick={() => reviewArtifact("detection", item.id, "approved")}>Approve</button>
                  <button className="ghost-button" onClick={() => reviewArtifact("detection", item.id, "rejected")}>Reject</button>
                  <button className="ghost-button" onClick={() => reviewArtifact("detection", item.id, "superseded")}>Supersede</button>
                </div>
                <div className="toolbar">
                  <input value={feedbackNote} onChange={(event) => setFeedbackNote(event.target.value)} placeholder="Feedback note" />
                  <button className="primary-button" onClick={() => sendFeedback("detection", item.id)}>Add feedback</button>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2>Mitigations</h2>
            <span>{artifacts?.summary.mitigation_count ?? 0} total</span>
          </div>
          <div className="stack-list">
            {(artifacts?.mitigations ?? []).map((item) => (
              <article className="line-card stacked-card" key={item.id}>
                <div>
                  <strong>{item.title}</strong>
                  <p>{item.artifact_type} · {item.status}</p>
                </div>
                <p className="muted">Review history: {item.review_history.length} · Feedback: {item.feedback.length}</p>
                {item.lineage?.supersedes_artifact_id ? (
                  <p className="muted">Supersedes artifact #{item.lineage.supersedes_artifact_id}</p>
                ) : null}
                {item.lineage?.correction_note ? <p className="muted">{item.lineage.correction_note}</p> : null}
                <pre className="code-card">{item.body}</pre>
                <div className="button-row">
                  <button className="ghost-button" onClick={() => reviewArtifact("mitigation", item.id, "under_review")}>Send review</button>
                  <button className="ghost-button" onClick={() => reviewArtifact("mitigation", item.id, "changes_requested")}>Request changes</button>
                  <button className="ghost-button" onClick={() => reviewArtifact("mitigation", item.id, "approved")}>Approve</button>
                  <button className="ghost-button" onClick={() => reviewArtifact("mitigation", item.id, "rejected")}>Reject</button>
                  <button className="ghost-button" onClick={() => reviewArtifact("mitigation", item.id, "superseded")}>Supersede</button>
                </div>
              </article>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}
