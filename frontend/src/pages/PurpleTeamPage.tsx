import { useState } from "react";

export function PurpleTeamPage() {
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [useCaldera, setUseCaldera] = useState(false);

  async function runReplay() {
    try {
      const resp = await fetch("/api/v6/purple-team/replay", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scope: { tenant: "demo" }, use_caldera: useCaldera }),
      });
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.detail || "Replay failed");
      setResult(body);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Replay failed");
    }
  }

  const gap = (result?.coverage_gap ?? {}) as Record<string, unknown>;

  return (
    <section className="operator-page">
      <div className="page-intro">
        <p className="eyebrow">Purple Team</p>
        <h1>Atomic Red Team replay and detection gap report</h1>
      </div>
      {error ? <div className="panel error-panel">{error}</div> : null}
      <section className="panel">
        <label className="checkbox-row">
          <input type="checkbox" checked={useCaldera} onChange={(e) => setUseCaldera(e.target.checked)} />
          Chain Caldera operation (lab-internal, egress locked)
        </label>
        <button className="primary-button" onClick={() => void runReplay()}>
          Run replay
        </button>
      </section>
      {result ? (
        <section className="panel">
          <h2>Coverage gap</h2>
          <p>
            Executed {String(gap.techniques_executed ?? 0)} techniques · detected {String(gap.detected_count ?? 0)} ·
            gaps {String(gap.gap_count ?? 0)}
          </p>
          <pre className="code-card">{JSON.stringify(result, null, 2)}</pre>
        </section>
      ) : null}
    </section>
  );
}
