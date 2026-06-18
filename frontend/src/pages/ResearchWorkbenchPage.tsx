import { useState } from "react";

export function ResearchWorkbenchPage() {
  const [target, setTarget] = useState("/lab/targets/sample.bin");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function runFuzz() {
    try {
      const resp = await fetch("/api/v6/research/fuzz", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_binary: target, engine: "afl", scope: { engagement: "lab" } }),
      });
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.detail || "Fuzz failed");
      setResult(body);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Fuzz failed");
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro">
        <p className="eyebrow">Research Workbench</p>
        <h1>Offensive research — fuzzing, debugging, crash triage</h1>
      </div>
      {error ? <div className="panel error-panel">{error}</div> : null}
      <section className="panel form-grid">
        <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="Target binary path" />
        <button className="primary-button" onClick={() => void runFuzz()}>
          Launch fuzz harness
        </button>
      </section>
      {result ? <pre className="code-card panel">{JSON.stringify(result, null, 2)}</pre> : null}
    </section>
  );
}
