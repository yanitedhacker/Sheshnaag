import { useEffect, useState } from "react";
import { api } from "../api";
import type { V3AnalysisCaseRecord, V3SpecimenRecord } from "../types";

function parseIds(value: string): number[] {
  return value
    .split(",")
    .map((item) => Number(item.trim()))
    .filter((item) => Number.isFinite(item) && item > 0);
}

export function AnalysisCasesPage() {
  const [cases, setCases] = useState<V3AnalysisCaseRecord[]>([]);
  const [specimens, setSpecimens] = useState<V3SpecimenRecord[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<number>(0);
  const [selectedCase, setSelectedCase] = useState<Record<string, unknown> | null>(null);
  const [title, setTitle] = useState("Phish-driven downloader case");
  const [analystName, setAnalystName] = useState("Demo Analyst");
  const [summary, setSummary] = useState("Track specimen lineage, findings, and report output for the initial malware case.");
  const [priority, setPriority] = useState("high");
  const [specimenIds, setSpecimenIds] = useState("");
  const [tags, setTags] = useState("email,malware");
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const [caseList, specimenList] = await Promise.all([api.listAnalysisCases(), api.listSpecimens()]);
    setCases(caseList.items);
    setSpecimens(specimenList.items);
    const defaultCaseId = selectedCaseId || caseList.items[0]?.id || 0;
    setSelectedCaseId(defaultCaseId);
    if (defaultCaseId) {
      const detail = await api.getAnalysisCase(defaultCaseId);
      setSelectedCase(detail as Record<string, unknown>);
    } else {
      setSelectedCase(null);
    }
    if (!specimenIds && specimenList.items[0]) {
      setSpecimenIds(String(specimenList.items[0].id));
    }
  }

  useEffect(() => {
    load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load V3 cases."));
  }, []);

  async function createCase() {
    try {
      await api.createAnalysisCase({
        title,
        analyst_name: analystName,
        summary,
        priority,
        specimen_ids: parseIds(specimenIds),
        tags: tags.split(",").map((item) => item.trim()).filter(Boolean),
      });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Case creation failed.");
    }
  }

  async function selectCase(caseId: number) {
    setSelectedCaseId(caseId);
    try {
      const detail = await api.getAnalysisCase(caseId);
      setSelectedCase(detail as Record<string, unknown>);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load case detail.");
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Analysis Cases</p>
          <h1>Case-centric malware investigations</h1>
          <p className="page-copy">Group specimens, findings, prevention outputs, AI drafts, and final reports under one tracked investigation case.</p>
        </div>
      </div>

      {error ? <div className="panel error-panel">{error}</div> : null}

      <section className="panel">
        <div className="panel-header">
          <h2>Create case</h2>
        </div>
        <div className="form-grid">
          <input value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Case title" />
          <input value={analystName} onChange={(event) => setAnalystName(event.target.value)} placeholder="Analyst" />
          <select value={priority} onChange={(event) => setPriority(event.target.value)}>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <input value={specimenIds} onChange={(event) => setSpecimenIds(event.target.value)} placeholder="Specimen IDs CSV" />
          <input value={tags} onChange={(event) => setTags(event.target.value)} placeholder="Tags CSV" />
          <textarea value={summary} onChange={(event) => setSummary(event.target.value)} placeholder="Summary" rows={3} />
          <button className="primary-button" onClick={() => void createCase()}>
            Open case
          </button>
        </div>
        {specimens.length ? (
          <p className="field-help">Known specimen IDs: {specimens.map((item) => `${item.id}:${item.name}`).join(" · ")}</p>
        ) : null}
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Caseboard</h2>
          <span>{cases.length} cases</span>
        </div>
        <div className="stack-list">
          {cases.map((item) => (
            <article className="line-card" key={item.id} onClick={() => void selectCase(item.id)}>
              <div>
                <strong>{item.title}</strong>
                <p>
                  {item.status} · priority {item.priority} · analyst {item.analyst_name}
                </p>
                <p className="muted">
                  {item.counts.specimens} specimens · {item.counts.findings} findings · {item.counts.prevention ?? 0} prevention ·{" "}
                  {item.counts.ai_sessions ?? 0} AI drafts · {item.counts.reports} reports
                </p>
              </div>
            </article>
          ))}
          {!cases.length ? <div className="empty-panel">No V3 analysis cases exist yet.</div> : null}
        </div>
      </section>

      {selectedCase ? (
        <section className="panel">
          <div className="panel-header">
            <h2>Case workflow</h2>
            <span>Case #{String(selectedCase.id ?? selectedCaseId)}</span>
          </div>
          <div className="stack-list">
            <article className="line-card stacked-card">
              <div>
                <strong>{String(selectedCase.title ?? "Case")}</strong>
                <p className="muted">{String(selectedCase.summary ?? "")}</p>
                <p className="muted">
                  Runs {Array.isArray(selectedCase.runs) ? selectedCase.runs.length : 0} · Findings{" "}
                  {Array.isArray(selectedCase.recent_findings) ? selectedCase.recent_findings.length : 0} · Indicators{" "}
                  {Array.isArray(selectedCase.indicators) ? selectedCase.indicators.length : 0}
                </p>
                <p className="muted">
                  Prevention {Array.isArray(selectedCase.prevention) ? selectedCase.prevention.length : 0} · Defang{" "}
                  {Array.isArray(selectedCase.defang) ? selectedCase.defang.length : 0} · AI drafts{" "}
                  {Array.isArray(selectedCase.ai_sessions) ? selectedCase.ai_sessions.length : 0}
                </p>
                <p className="muted">
                  Policy: {String((selectedCase.policy as { name?: string } | undefined)?.name ?? "Default V3 Scope Policy")}
                </p>
              </div>
            </article>
          </div>
        </section>
      ) : null}
    </section>
  );
}
