import { useEffect, useState } from "react";
import { api } from "../api";
import type { V3AIProvider, V3AISessionRecord, V3AnalysisCaseRecord } from "../types";

export function AISessionsPage() {
  const [providers, setProviders] = useState<V3AIProvider[]>([]);
  const [cases, setCases] = useState<V3AnalysisCaseRecord[]>([]);
  const [items, setItems] = useState<V3AISessionRecord[]>([]);
  const [analysisCaseId, setAnalysisCaseId] = useState<number>(0);
  const [providerKey, setProviderKey] = useState("goodbear-cli");
  const [capability, setCapability] = useState("draft_report_sections");
  const [prompt, setPrompt] = useState("Summarize the grounded evidence into a draft incident report section.");
  const [createdBy, setCreatedBy] = useState("Demo Analyst");
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const [providerList, caseList, sessionList] = await Promise.all([api.listAIProviders(), api.listAnalysisCases(), api.listAISessions()]);
    setProviders(providerList.items);
    setCases(caseList.items);
    setItems(sessionList.items);
    if (!analysisCaseId && caseList.items[0]) {
      setAnalysisCaseId(caseList.items[0].id);
    }
    if (!providerKey && providerList.items[0]) {
      setProviderKey(providerList.items[0].provider_key);
    }
  }

  useEffect(() => {
    load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load AI sessions."));
  }, []);

  async function createSession() {
    if (!analysisCaseId) {
      return;
    }
    try {
      await api.createAISession({
        analysis_case_id: analysisCaseId,
        provider_key: providerKey,
        capability,
        prompt,
        grounding: {
          items: [
            {
              label: "case",
              summary: `Analysis case ${analysisCaseId}`,
            },
          ],
        },
        created_by: createdBy,
      });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "AI draft creation failed.");
    }
  }

  async function reviewSession(sessionId: number, decision: string) {
    try {
      await api.reviewAISession({ session_id: sessionId, reviewer_name: "Lead Reviewer", decision });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "AI review failed.");
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">AI Sessions and Drafts</p>
          <h1>Guardrailed frontier-AI assistance</h1>
          <p className="page-copy">Use approved providers as grounded analyst copilots for clustering, hypothesis drafting, prevention candidates, and report sections.</p>
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
          <select value={providerKey} onChange={(event) => setProviderKey(event.target.value)}>
            {providers.map((item) => (
              <option key={item.provider_key} value={item.provider_key}>
                {item.display_name} · {item.status ?? "unknown"}
              </option>
            ))}
          </select>
          <select value={capability} onChange={(event) => setCapability(event.target.value)}>
            <option value="draft_report_sections">Draft report sections</option>
            <option value="summarize_evidence">Summarize evidence</option>
            <option value="cluster_iocs">Cluster IOCs</option>
            <option value="draft_hypotheses">Draft hypotheses</option>
            <option value="generate_detection_candidates">Generate detection candidates</option>
            <option value="draft_mitigation">Draft mitigation</option>
            <option value="variant_diff_review">Variant diff review</option>
          </select>
          <input value={createdBy} onChange={(event) => setCreatedBy(event.target.value)} placeholder="Created by" />
          <textarea value={prompt} onChange={(event) => setPrompt(event.target.value)} placeholder="Prompt" rows={4} />
          <button className="primary-button" onClick={() => void createSession()}>
            Create AI draft
          </button>
        </div>
        {providers.find((item) => item.provider_key === providerKey) ? (
          <p className="field-help">
            Provider health: {String(providers.find((item) => item.provider_key === providerKey)?.status ?? "unknown")} · model{" "}
            {String(providers.find((item) => item.provider_key === providerKey)?.model_label ?? "n/a")}
          </p>
        ) : null}
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>Draft sessions</h2>
          <span>{items.length}</span>
        </div>
        <div className="stack-list">
          {items.map((item) => (
            <article className="line-card stacked-card" key={item.id}>
              <div>
                <strong>{item.provider_key}</strong>
                <p>
                  {item.capability} · {item.review_state} · case #{item.analysis_case_id}
                </p>
                <p className="muted">
                  Execution {String(item.output_payload.execution_status ?? "unknown")} · prompt version{" "}
                  {String(item.output_payload.prompt_version ?? "n/a")}
                </p>
              </div>
              <pre className="code-card">{item.output_markdown}</pre>
              <div className="button-row">
                <button className="ghost-button" onClick={() => void reviewSession(item.id, "under_review")}>Review</button>
                <button className="ghost-button" onClick={() => void reviewSession(item.id, "approved")}>Approve</button>
              </div>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
}
