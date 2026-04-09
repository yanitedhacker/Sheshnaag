import { useEffect, useState } from "react";
import { api } from "../api";
import type { LedgerResponse } from "../types";

export function AnalystLedgerPage() {
  const [ledger, setLedger] = useState<LedgerResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.getLedger()
      .then(setLedger)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load analyst ledger."));
  }, []);

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Analyst Ledger</p>
          <h1>Contribution scoring and review credit</h1>
          <p className="page-copy">See which analysts authored, reviewed, and exported Sheshnaag work across the current workspace.</p>
        </div>
      </div>

      {error ? <div className="panel error-panel">{error}</div> : null}

      <div className="panel-grid">
        <section className="panel">
          <div className="panel-header">
            <h2>Scoreboard</h2>
            <span>{ledger?.summary.total_score ?? 0} total points</span>
          </div>
          <div className="stack-list">
            {(ledger?.summary.by_analyst ?? []).map((item) => (
              <article className="line-card" key={item.name}>
                <div>
                  <strong>{item.name}</strong>
                  <p>Aggregated analyst credit</p>
                </div>
                <span>{item.score.toFixed(1)}</span>
              </article>
            ))}
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2>Entries</h2>
            <span>{ledger?.count ?? 0} rows</span>
          </div>
          <div className="stack-list">
            {(ledger?.items ?? []).slice(0, 20).map((item) => (
              <article className="line-card" key={item.id}>
                <div>
                  <strong>{item.entry_type}</strong>
                  <p>{item.analyst_name ?? "system"} · {item.object_type} {item.object_id}</p>
                </div>
                <span>{item.score.toFixed(1)}</span>
              </article>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}
