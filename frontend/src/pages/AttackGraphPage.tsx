import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

export function AttackGraphPage() {
  const graph = useQuery({ queryKey: ["graph"], queryFn: () => api.getGraph() });

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
          {graph.data.paths.map((path) => (
            <article key={path.summary} className="path-card">
              <div className="list-row">
                <strong>{path.summary}</strong>
                <span className="pill high">score {path.score}</span>
              </div>
              <div className="path-diagram">
                {path.labels.map((label, index) => (
                  <div key={`${label}-${index}`} className="path-diagram">
                    <span className="path-node">{label}</span>
                    {index < path.labels.length - 1 && <span className="arrow">→</span>}
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
        <div className="action-list">
          {graph.data.nodes.slice(0, 12).map((node) => (
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
