import { useEffect, useState } from "react";
import { api } from "../api";
import type { V3SpecimenRecord } from "../types";

export function SpecimenIntakePage() {
  const [items, setItems] = useState<V3SpecimenRecord[]>([]);
  const [name, setName] = useState("sample-eml");
  const [specimenKind, setSpecimenKind] = useState("email");
  const [sourceType, setSourceType] = useState("upload");
  const [sourceReference, setSourceReference] = useState("mailbox://sample.eml");
  const [submittedBy, setSubmittedBy] = useState("Demo Analyst");
  const [summary, setSummary] = useState("Suspicious inbound specimen captured for safe triage.");
  const [labels, setLabels] = useState("phish,initial-access");
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const data = await api.listSpecimens();
    setItems(data.items);
  }

  useEffect(() => {
    load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load specimens."));
  }, []);

  async function createSpecimen() {
    try {
      await api.createSpecimen({
        name,
        specimen_kind: specimenKind,
        source_type: sourceType,
        source_reference: sourceReference,
        submitted_by: submittedBy,
        summary,
        labels: labels.split(",").map((item) => item.trim()).filter(Boolean),
      });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Specimen creation failed.");
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Specimen Intake</p>
          <h1>Quarantine-first malware intake</h1>
          <p className="page-copy">Register files, URLs, emails, and archives into the V3 malware lane with immutable revisions and safe-render metadata.</p>
        </div>
      </div>

      {error ? <div className="panel error-panel">{error}</div> : null}

      <section className="panel">
        <div className="panel-header">
          <h2>New specimen</h2>
        </div>
        <div className="form-grid">
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Specimen name" />
          <select value={specimenKind} onChange={(event) => setSpecimenKind(event.target.value)}>
            <option value="file">File</option>
            <option value="archive">Archive</option>
            <option value="url">URL</option>
            <option value="email">Email</option>
          </select>
          <select value={sourceType} onChange={(event) => setSourceType(event.target.value)}>
            <option value="upload">Upload</option>
            <option value="url_import">URL import</option>
            <option value="mailbox">Mailbox</option>
            <option value="derived">Derived</option>
          </select>
          <input value={sourceReference} onChange={(event) => setSourceReference(event.target.value)} placeholder="Source reference" />
          <input value={submittedBy} onChange={(event) => setSubmittedBy(event.target.value)} placeholder="Submitted by" />
          <input value={labels} onChange={(event) => setLabels(event.target.value)} placeholder="Labels CSV" />
          <textarea value={summary} onChange={(event) => setSummary(event.target.value)} placeholder="Summary" rows={3} />
          <button className="primary-button" onClick={() => void createSpecimen()}>
            Intake specimen
          </button>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Quarantine registry</h2>
          <span>{items.length} specimens</span>
        </div>
        <div className="stack-list">
          {items.map((item) => (
            <article className="line-card stacked-card" key={item.id}>
              <div>
                <strong>{item.name}</strong>
                <p>
                  {item.specimen_kind} · {item.status} · risk {item.risk_level}
                </p>
                <p className="muted">
                  Revision {item.latest_revision_number} · submitted by {item.submitted_by ?? "unknown"}
                </p>
                {item.detonation_eligibility ? (
                  <p className="muted">
                    Detonation: {String(item.detonation_eligibility.eligible ? "eligible" : "blocked")} · mode{" "}
                    {String(item.detonation_eligibility.recommended_analysis_mode ?? "review")}
                  </p>
                ) : null}
                {item.latest_revision ? (
                  <>
                    <p className="muted">SHA-256 {item.latest_revision.sha256.slice(0, 18)}...</p>
                    <p className="muted">{item.latest_revision.quarantine_path}</p>
                    <p className="muted">
                      Safe render: {String(item.latest_revision.safe_rendering.render_mode ?? "unknown")} · export{" "}
                      {item.latest_revision.export_review_state ?? "pending_review"}
                    </p>
                    <p className="muted">
                      Pipeline:{" "}
                      {item.latest_revision.processing_stages
                        .map((stage) => `${String(stage.stage)}:${String(stage.status)}`)
                        .join(" · ")}
                    </p>
                  </>
                ) : null}
              </div>
            </article>
          ))}
          {!items.length ? <div className="empty-panel">No specimens have been registered yet.</div> : null}
        </div>
      </section>
    </section>
  );
}
