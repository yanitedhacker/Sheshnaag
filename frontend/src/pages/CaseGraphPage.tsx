import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { CaseGraphResponse, V3AnalysisCaseListResponse } from "../types";

export function CaseGraphPage() {
  const [cases, setCases] = useState<V3AnalysisCaseListResponse["items"]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<number | null>(null);
  const [graph, setGraph] = useState<CaseGraphResponse | null>(null);
  const [depth, setDepth] = useState<number>(2);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    let cancelled = false;
    api
      .listAnalysisCases()
      .then((response) => {
        if (cancelled) return;
        setCases(response.items ?? []);
        if (response.items?.length && selectedCaseId == null) {
          setSelectedCaseId(response.items[0].id);
        }
      })
      .catch((exc: Error) => {
        if (!cancelled) setError(exc.message);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (selectedCaseId == null) {
      setGraph(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .getCaseGraph(selectedCaseId, depth)
      .then((response) => {
        if (cancelled) return;
        setGraph(response);
      })
      .catch((exc: Error) => {
        if (!cancelled) setError(exc.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedCaseId, depth]);

  const nodesByType = useMemo(() => {
    if (!graph) return new Map<string, number>();
    const counts = new Map<string, number>();
    graph.nodes.forEach((node) => {
      counts.set(node.node_type, (counts.get(node.node_type) ?? 0) + 1);
    });
    return counts;
  }, [graph]);

  return (
    <section className="page-section">
      <header className="page-header">
        <h1>Case Graph</h1>
        <p className="page-subtitle">
          Subgraph view anchored on an analysis case. Nodes expand outward through
          IOC pivot edges so you can see the linked specimens, indicators, and
          findings without leaving the case.
        </p>
      </header>

      <div className="case-graph-controls">
        <label className="checkbox-row">
          <span>Case</span>
          <select
            value={selectedCaseId ?? ""}
            onChange={(event) => {
              const next = Number(event.target.value);
              setSelectedCaseId(Number.isNaN(next) ? null : next);
            }}
          >
            <option value="" disabled>
              Select case
            </option>
            {cases.map((caseRow) => (
              <option key={caseRow.id} value={caseRow.id}>
                {caseRow.title || `Case ${caseRow.id}`}
              </option>
            ))}
          </select>
        </label>
        <label className="checkbox-row">
          <span>Depth</span>
          <input
            type="number"
            min={0}
            max={5}
            value={depth}
            onChange={(event) => setDepth(Number(event.target.value) || 0)}
          />
        </label>
      </div>

      {error ? <div className="status-pill status-danger">{error}</div> : null}
      {loading ? <div className="status-pill">Loading case graph…</div> : null}

      {graph?.case ? (
        <div className="case-graph-summary">
          <h2>{graph.case.name || `Case ${graph.case.id}`}</h2>
          <p>
            Indicators: {graph.case.indicator_count} · Findings: {graph.case.finding_count} ·
            Nodes: {graph.nodes.length} · Edges: {graph.edges.length} · Depth: {graph.depth}
          </p>
        </div>
      ) : null}

      {graph ? (
        <div className="case-graph-grid">
          <article className="case-graph-card">
            <h3>Node mix</h3>
            <ul>
              {Array.from(nodesByType.entries())
                .sort(([, a], [, b]) => b - a)
                .map(([nodeType, count]) => (
                  <li key={nodeType}>
                    <strong>{nodeType}</strong>: {count}
                  </li>
                ))}
            </ul>
          </article>

          <article className="case-graph-card">
            <h3>Nodes ({graph.nodes.length})</h3>
            <ul className="case-graph-list">
              {graph.nodes.slice(0, 100).map((node) => (
                <li key={`${node.node_type}-${node.id}`}>
                  <span className="status-pill">{node.node_type}</span> {node.label}
                </li>
              ))}
            </ul>
            {graph.nodes.length > 100 ? (
              <p className="muted">Showing the first 100 nodes; broaden filters to drill in.</p>
            ) : null}
          </article>

          <article className="case-graph-card">
            <h3>Edges ({graph.edges.length})</h3>
            <ul className="case-graph-list">
              {graph.edges.slice(0, 100).map((edge) => (
                <li key={`${edge.edge_type}-${edge.id}`}>
                  <span className="status-pill">{edge.edge_type}</span>{" "}
                  {edge.from_node_id} → {edge.to_node_id} · weight {edge.weight.toFixed(2)}
                </li>
              ))}
            </ul>
          </article>
        </div>
      ) : null}
    </section>
  );
}
