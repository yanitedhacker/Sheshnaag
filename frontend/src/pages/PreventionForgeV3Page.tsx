import { useEffect, useState } from "react";
import { api } from "../api";
import type { V3AnalysisCaseRecord, V3PreventionRecord } from "../types";

export function PreventionForgeV3Page() {
  const [cases, setCases] = useState<V3AnalysisCaseRecord[]>([]);
  const [items, setItems] = useState<V3PreventionRecord[]>([]);
  const [analysisCaseId, setAnalysisCaseId] = useState<number>(0);
  const [artifactType, setArtifactType] = useState("yara");
  const [name, setName] = useState("Downloader family rule");
  const [body, setBody] = useState("rule downloader_family { condition: true }");
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const [caseList, preventionList] = await Promise.all([api.listAnalysisCases(), api.listPrevention()]);
    setCases(caseList.items);
    setItems(preventionList.items);
    if (!analysisCaseId && caseList.items[0]) {
      setAnalysisCaseId(caseList.items[0].id);
    }
  }

  useEffect(() => {
    load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load prevention artifacts."));
  }, []);

  async function createArtifact() {
    if (!analysisCaseId) {
      return;
    }
    try {
      await api.createPrevention({
        analysis_case_id: analysisCaseId,
        artifact_type: artifactType,
        name,
        body,
      });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Prevention artifact creation failed.");
    }
  }

  async function reviewArtifact(artifactId: number, decision: string) {
    try {
      await api.reviewPrevention({ artifact_id: artifactId, reviewer_name: "Lead Reviewer", decision });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Prevention review failed.");
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Prevention Forge</p>
          <h1>Turn findings into defensive controls</h1>
          <p className="page-copy">Draft YARA, Sigma, mail rules, blocklists, and hardening outputs backed by case evidence and review history.</p>
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
          <select value={artifactType} onChange={(event) => setArtifactType(event.target.value)}>
            <option value="yara">YARA</option>
            <option value="sigma">Sigma</option>
            <option value="suricata">Suricata</option>
            <option value="mail_rule">Mail rule</option>
            <option value="blocklist">Blocklist</option>
          </select>
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Artifact name" />
          <textarea value={body} onChange={(event) => setBody(event.target.value)} placeholder="Artifact body" rows={4} />
          <button className="primary-button" onClick={() => void createArtifact()}>
            Add prevention artifact
          </button>
        </div>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>Artifacts</h2>
          <span>{items.length}</span>
        </div>
        <div className="stack-list">
          {items.map((item) => (
            <article className="line-card stacked-card" key={item.id}>
              <div>
                <strong>{item.name}</strong>
                <p>
                  {item.artifact_type} · {item.status}
                </p>
              </div>
              <pre className="code-card">{item.body}</pre>
              <div className="button-row">
                <button className="ghost-button" onClick={() => void reviewArtifact(item.id, "under_review")}>Review</button>
                <button className="ghost-button" onClick={() => void reviewArtifact(item.id, "approved")}>Approve</button>
              </div>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
}
