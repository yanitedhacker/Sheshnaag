import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

export function CveDetailPage() {
  const { cveId } = useParams();
  const query = useQuery({
    queryKey: ["cve", cveId],
    queryFn: () => api.getCve(cveId!),
    enabled: Boolean(cveId),
  });

  if (query.isLoading) {
    return <section className="panel">Loading CVE...</section>;
  }

  if (query.error || !query.data) {
    return <section className="panel">Unable to load this CVE.</section>;
  }

  const cve = query.data;

  return (
    <section className="detail-card">
      <div className="detail-header">
        <div>
          <p className="eyebrow">CVE Detail</p>
          <h3>{cve.cve_id}</h3>
        </div>
        {cve.intel?.kev?.present && <span className="pill critical">KEV</span>}
      </div>

      <div className="metric-grid">
        <article className="metric-card">
          <div className="metric-value">{cve.cvss_v3_score ?? "—"}</div>
          <div className="metric-label">CVSS v3</div>
        </article>
        <article className="metric-card">
          <div className="metric-value">{cve.risk?.overall_score?.toFixed(1) ?? "—"}</div>
          <div className="metric-label">Risk score</div>
        </article>
        <article className="metric-card">
          <div className="metric-value">{cve.intel?.epss ? (cve.intel.epss.score * 100).toFixed(1) : "—"}%</div>
          <div className="metric-label">EPSS</div>
        </article>
      </div>

      <p>{cve.description}</p>

      <section className="panel">
        <p className="eyebrow">ATT&CK Context</p>
        <div className="action-list">
          {(cve.intel?.attack_techniques ?? []).map((technique) => (
            <article key={technique.external_id} className="asset-card">
              <div className="list-row">
                <strong>{technique.external_id}</strong>
                <span className="pill neutral">{technique.tactic ?? "Technique"}</span>
              </div>
              <p className="muted">{technique.name}</p>
              {technique.source_url && (
                <a href={technique.source_url} target="_blank" rel="noreferrer">
                  Open source
                </a>
              )}
            </article>
          ))}
        </div>
      </section>

      <section className="panel">
        <p className="eyebrow">Affected Products</p>
        <div className="action-list">
          {(cve.affected_products ?? []).map((product) => (
            <article key={`${product.vendor}-${product.product}-${product.version ?? ""}`} className="asset-card">
              <strong>{product.vendor}/{product.product}</strong>
              <p className="muted">{product.version ?? "version unspecified"}</p>
            </article>
          ))}
        </div>
      </section>

      <Link className="ghost-button" to="/">
        Back to workbench
      </Link>
    </section>
  );
}
