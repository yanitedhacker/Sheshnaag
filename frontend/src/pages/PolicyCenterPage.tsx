import { useEffect, useState } from "react";
import { api } from "../api";
import type { V3PolicyRecord } from "../types";

export function PolicyCenterPage() {
  const [items, setItems] = useState<V3PolicyRecord[]>([]);
  const [name, setName] = useState("Strict bounty export policy");
  const [policyBody, setPolicyBody] = useState(
    JSON.stringify(
      {
        allowed_specimen_classes: ["file", "archive", "url", "email"],
        allowed_collectors: ["process_tree", "browser_session", "ioc_extractor", "static_triage"],
        allowed_egress_modes: ["default_deny", "sinkhole"],
        allowed_ai_providers: ["goodbear-cli", "openai-api"],
        unsafe_export_requires_approval: true,
      },
      null,
      2,
    ),
  );
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const data = await api.listPolicies();
    setItems(data.items);
  }

  useEffect(() => {
    load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load scope policies."));
  }, []);

  async function createPolicy() {
    try {
      await api.createPolicy({
        name,
        policy: JSON.parse(policyBody) as Record<string, unknown>,
      });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Policy creation failed.");
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Policy Center</p>
          <h1>Scope and export guardrails</h1>
          <p className="page-copy">Control specimen classes, AI providers, egress modes, and export safety checks for the V3 malware lab.</p>
        </div>
      </div>
      {error ? <div className="panel error-panel">{error}</div> : null}
      <section className="panel">
        <div className="form-grid">
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Policy name" />
          <textarea value={policyBody} onChange={(event) => setPolicyBody(event.target.value)} rows={10} />
          <button className="primary-button" onClick={() => void createPolicy()}>
            Save policy
          </button>
        </div>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>Policies</h2>
          <span>{items.length}</span>
        </div>
        <div className="stack-list">
          {items.map((item) => (
            <article className="line-card stacked-card" key={item.id}>
              <div>
                <strong>{item.name}</strong>
                <p>
                  {item.status}
                  {item.is_default ? " · default" : ""}
                </p>
              </div>
              <pre className="code-card">{JSON.stringify(item.policy, null, 2)}</pre>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
}
