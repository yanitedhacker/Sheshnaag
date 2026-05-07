import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type {
  CaseLifecycleState,
  CaseQueueItem,
  CaseQueueResponse,
} from "../types";

const STATES: CaseLifecycleState[] = [
  "triage",
  "analysis",
  "review",
  "ready_to_ship",
  "shipped",
  "archived",
];

const STATE_LABELS: Record<CaseLifecycleState, string> = {
  triage: "Triage",
  analysis: "Analysis",
  review: "Review",
  ready_to_ship: "Ready",
  shipped: "Shipped",
  archived: "Archived",
};

function formatTs(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

export function CaseLifecycleQueue() {
  const [active, setActive] = useState<CaseLifecycleState>("triage");
  const [data, setData] = useState<CaseQueueResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [busyCaseId, setBusyCaseId] = useState<number | null>(null);

  async function refresh() {
    setLoading(true);
    try {
      const response = await api.getCaseQueue(active, 100);
      setData(response);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  async function handleTransition(item: CaseQueueItem, target: CaseLifecycleState) {
    setBusyCaseId(item.case_id);
    try {
      await api.transitionCase(item.case_id, target);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyCaseId(null);
    }
  }

  const counts = useMemo(() => data?.state_counts ?? null, [data]);

  return (
    <section className="panel">
      <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h2>Case lifecycle</h2>
        <button className="ghost-button" onClick={refresh} disabled={loading}>
          {loading ? "Loading…" : "Refresh"}
        </button>
      </div>

      <div className="tab-strip" role="tablist" style={{ display: "flex", gap: "0.25rem", marginBottom: "0.75rem", flexWrap: "wrap" }}>
        {STATES.map((s) => (
          <button
            key={s}
            role="tab"
            aria-selected={s === active}
            className={s === active ? "tab-button is-active" : "tab-button"}
            onClick={() => setActive(s)}
          >
            {STATE_LABELS[s]}
            {counts ? <span className="tab-count"> ({counts[s] ?? 0})</span> : null}
          </button>
        ))}
      </div>

      {error ? <div className="callout callout-danger">{error}</div> : null}

      <table className="data-table">
        <thead>
          <tr>
            <th>Case</th>
            <th>Title</th>
            <th>Analyst</th>
            <th>State changed</th>
            <th>Last actor</th>
            <th>Transitions</th>
          </tr>
        </thead>
        <tbody>
          {data && data.items.length === 0 && !loading ? (
            <tr>
              <td colSpan={6} style={{ textAlign: "center", padding: "1.5rem", opacity: 0.6 }}>
                No cases in {STATE_LABELS[active]}.
              </td>
            </tr>
          ) : null}
          {data?.items.map((item) => (
            <tr key={item.case_id}>
              <td>#{item.case_id}</td>
              <td>{item.title}</td>
              <td>{item.analyst_name}</td>
              <td>{formatTs(item.state_changed_at)}</td>
              <td>{item.last_transition_actor ?? "—"}</td>
              <td>
                {item.legal_transitions_for_caller.length === 0 ? (
                  <span style={{ opacity: 0.5 }}>(no role permission)</span>
                ) : (
                  <div style={{ display: "flex", gap: "0.25rem", flexWrap: "wrap" }}>
                    {item.legal_transitions_for_caller.map((target) => (
                      <button
                        key={target}
                        className="ghost-button small"
                        disabled={busyCaseId === item.case_id}
                        onClick={() => handleTransition(item, target)}
                      >
                        → {STATE_LABELS[target]}
                      </button>
                    ))}
                  </div>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
