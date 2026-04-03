import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

export function PatchDetailPage() {
  const { patchId } = useParams();
  const query = useQuery({
    queryKey: ["patch", patchId],
    queryFn: () => api.getPatch(patchId!),
    enabled: Boolean(patchId),
  });

  if (query.isLoading) {
    return <section className="panel">Loading patch...</section>;
  }

  if (query.error || !query.data) {
    return <section className="panel">Unable to load this patch.</section>;
  }

  const patch = query.data;

  return (
    <section className="detail-card">
      <div className="detail-header">
        <div>
          <p className="eyebrow">Patch Detail</p>
          <h3>{patch.patch.patch_id}</h3>
        </div>
        {patch.patch.requires_reboot && <span className="pill high">Reboot required</span>}
      </div>

      <div className="metric-grid">
        <article className="metric-card">
          <div className="metric-value">{patch.patch.vendor}</div>
          <div className="metric-label">Vendor</div>
        </article>
        <article className="metric-card">
          <div className="metric-value">{patch.patch.estimated_downtime_minutes ?? "—"}</div>
          <div className="metric-label">Downtime (min)</div>
        </article>
      </div>

      <section className="panel">
        <p className="eyebrow">Linked CVEs</p>
        <div className="action-list">
          {patch.linked_cves.map((cve) => (
            <article key={cve.cve_id} className="asset-card">
              <div className="list-row">
                <Link to={`/cves/${cve.cve_id}`}>{cve.cve_id}</Link>
                {cve.exploit_available && <span className="pill critical">Exploit</span>}
              </div>
              <p className="muted">CVSS {cve.cvss_v3_score ?? "N/A"}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="panel">
        <p className="eyebrow">Asset Mappings</p>
        <div className="action-list">
          {patch.asset_mappings.map((mapping) => (
            <article key={`${mapping.asset_id}-${mapping.maintenance_window ?? ""}`} className="asset-card">
              <strong>Asset #{mapping.asset_id}</strong>
              <p className="muted">{mapping.maintenance_window ?? "Window TBD"}</p>
            </article>
          ))}
        </div>
      </section>

      {patch.approvals && patch.approvals.length > 0 && (
        <section className="panel">
          <p className="eyebrow">Approval Workflow</p>
          <div className="action-list">
            {patch.approvals.map((approval) => (
              <article key={approval.id} className="asset-card">
                <div className="list-row">
                  <strong>{approval.approval_type}</strong>
                  <span className="pill neutral">{approval.approval_state}</span>
                </div>
                <p className="muted">{approval.note}</p>
              </article>
            ))}
          </div>
        </section>
      )}

      {patch.patch.advisory_url && (
        <a className="primary-button" href={patch.patch.advisory_url} target="_blank" rel="noreferrer">
          Open advisory
        </a>
      )}
    </section>
  );
}
