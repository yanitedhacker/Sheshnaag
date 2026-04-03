import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

export function TrustCenterPage() {
  const trust = useQuery({ queryKey: ["model-trust"], queryFn: api.getModelTrust });

  if (trust.isLoading) {
    return <section className="panel">Loading model trust snapshot...</section>;
  }

  if (trust.error || !trust.data) {
    return <section className="panel">Unable to load the trust center.</section>;
  }

  return (
    <section className="trust-grid">
      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Model Trust</p>
            <h3>Version {trust.data.model_version}</h3>
            <p className="muted">Training date {trust.data.training_date ?? "Not available"}</p>
          </div>
          <span className={`pill ${trust.data.drift.status === "stable" ? "neutral" : "high"}`}>
            {trust.data.drift.status}
          </span>
        </div>

        <div className="metric-grid">
          <article className="metric-card">
            <div className="metric-value">{trust.data.coverage.recent_scores}</div>
            <div className="metric-label">Recent scores</div>
          </article>
          <article className="metric-card">
            <div className="metric-value">{trust.data.drift.delta_vs_epss.toFixed(3)}</div>
            <div className="metric-label">Delta vs EPSS</div>
          </article>
          <article className="metric-card">
            <div className="metric-value">{trust.data.coverage.knowledge_chunks}</div>
            <div className="metric-label">Knowledge chunks</div>
          </article>
          <article className="metric-card">
            <div className="metric-value">{trust.data.retrieval.index_status}</div>
            <div className="metric-label">Retrieval index</div>
          </article>
        </div>

        <div className="chart-row">
          {trust.data.feature_importance.map((feature) => (
            <div key={feature.feature} className="bar-row">
              <span>{feature.feature}</span>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${Math.min(100, feature.frequency * 10)}%` }} />
              </div>
              <strong>{feature.frequency}</strong>
            </div>
          ))}
        </div>
      </section>

      <section className="detail-card">
        <p className="eyebrow">Calibration</p>
        <div className="chart-row">
          {trust.data.calibration_curve.map((point) => (
            <div key={point.predicted_probability_bucket} className="bar-row">
              <span>{point.predicted_probability_bucket.toFixed(1)}</span>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${Math.min(100, point.average_risk_score)}%` }} />
              </div>
              <strong>{point.average_risk_score}</strong>
            </div>
          ))}
        </div>

        <div className="panel">
          <p className="eyebrow">Notes</p>
          <div className="action-list">
            {trust.data.notes.map((note) => (
              <article key={note} className="asset-card">
                {note}
              </article>
            ))}
          </div>
        </div>

        <div className="panel">
          <p className="eyebrow">Analyst Feedback Loop</p>
          <div className="inline-meta">
            {Object.entries(trust.data.analyst_feedback.summary).map(([key, value]) => (
              <span key={key}>{key}: {value}</span>
            ))}
          </div>
          <div className="action-list">
            {trust.data.analyst_feedback.recent_items.map((item) => (
              <article key={item.id} className="asset-card">
                <div className="list-row">
                  <strong>{item.action_id}</strong>
                  <span className="pill neutral">{item.feedback_type}</span>
                </div>
                <p className="muted">{item.note}</p>
              </article>
            ))}
          </div>
        </div>

        <div className="panel">
          <p className="eyebrow">Retrieval & Baselines</p>
          <div className="inline-meta">
            <span>Embedding model {trust.data.retrieval.embedding_model}</span>
            <span>Average model probability {trust.data.baselines.model_average.toFixed(3)}</span>
            <span>Average EPSS {trust.data.baselines.epss_average.toFixed(3)}</span>
          </div>
          <div className="chart-row">
            {trust.data.score_history.map((point) => (
              <div key={`${point.created_at}-${point.overall_score}`} className="bar-row">
                <span>{point.exploit_probability.toFixed(2)}</span>
                <div className="bar-track">
                  <div className="bar-fill" style={{ width: `${Math.min(100, point.overall_score)}%` }} />
                </div>
                <strong>{point.overall_score.toFixed(0)}</strong>
              </div>
            ))}
          </div>
        </div>
      </section>
    </section>
  );
}
