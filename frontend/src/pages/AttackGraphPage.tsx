import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

export function AttackGraphPage() {
  const graph = useQuery({ queryKey: ["graph"], queryFn: () => api.getGraph() });
  const [selectedPathIndex, setSelectedPathIndex] = useState(0);

  const selectedPath = graph.data?.paths[selectedPathIndex] ?? graph.data?.paths[0];
  const selectedNodeSet = useMemo(() => new Set(selectedPath?.node_ids ?? []), [selectedPath]);
  const selectedNodes = useMemo(
    () => graph.data?.nodes.filter((node) => selectedNodeSet.has(node.id)) ?? [],
    [graph.data?.nodes, selectedNodeSet],
  );

  if (graph.isLoading) {
    return <section className="panel">Loading attack graph...</section>;
  }

  if (graph.error || !graph.data) {
    return <section className="panel">Unable to load attack paths.</section>;
  }

  return (
    <section className="graph-grid">
      <section className="list-card">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Attack Paths</p>
            <h3>From exposure to exploitable outcome</h3>
          </div>
          <span className="pill neutral">{graph.data.cached ? "cached" : "fresh"}</span>
        </div>
        <div className="path-list">
          {graph.data.paths.map((path, index) => (
            <article
              key={path.summary}
              className={`path-card interactive-card ${selectedPathIndex === index ? "active" : ""}`}
              onClick={() => setSelectedPathIndex(index)}
            >
              <div className="list-row">
                <strong>{path.summary}</strong>
                <span className="pill high">score {path.score}</span>
              </div>
              <div className="path-diagram">
                {path.labels.map((label, labelIndex) => (
                  <div key={`${label}-${labelIndex}`} className="path-diagram">
                    <span className="path-node">{label}</span>
                    {labelIndex < path.labels.length - 1 && <span className="arrow">→</span>}
                  </div>
                ))}
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="detail-card">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Graph Snapshot</p>
            <h3>Persisted graph nodes and edges</h3>
          </div>
        </div>
        <div className="metric-grid">
          <article className="metric-card">
            <div className="metric-value">{graph.data.nodes.length}</div>
            <div className="metric-label">Nodes</div>
          </article>
          <article className="metric-card">
            <div className="metric-value">{graph.data.edges.length}</div>
            <div className="metric-label">Edges</div>
          </article>
          <article className="metric-card">
            <div className="metric-value">{graph.data.paths.length}</div>
            <div className="metric-label">Top paths</div>
          </article>
        </div>

        {selectedPath && (
          <div className="panel inset">
            <p className="eyebrow">Selected Path</p>
            <strong>{selectedPath.summary}</strong>
            <p className="muted">Edge types: {selectedPath.edge_types.join(" → ")}</p>
          </div>
        )}

        <div className="action-list">
          {selectedNodes.map((node) => (
            <article key={node.id} className="asset-card">
              <div className="list-row">
                <strong>{node.label}</strong>
                <span className="pill neutral">{node.node_type}</span>
              </div>
              <p className="muted">{node.node_key}</p>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
}
