import { useEffect, useState } from "react";
import { api } from "../api";
import type { DisclosureBundleRecord, IntelOverviewResponse, RunSummary } from "../types";

export function IntelDashboardPage() {
  const [overview, setOverview] = useState<IntelOverviewResponse | null>(null);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [bundles, setBundles] = useState<DisclosureBundleRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [intel, runList, disclosureList] = await Promise.all([
          api.getIntelOverview(),
          api.listRuns(),
          api.listDisclosures(),
        ]);
        if (cancelled) {
          return;
        }
        setOverview(intel);
        setRuns(runList.items.slice(0, 6));
        setBundles(disclosureList.items.slice(0, 4));
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load intel dashboard.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Intel Dashboard</p>
          <h1>Operator readiness at a glance</h1>
          <p className="page-copy">
            Feed freshness, recent validation activity, and export posture for the current Sheshnaag workspace.
          </p>
        </div>
      </div>

      {error ? <div className="panel error-panel">{error}</div> : null}

      <div className="stats-grid">
        <article className="stat-card">
          <span className="stat-label">Candidates</span>
          <strong>{overview?.summary?.candidate_count ?? 0}</strong>
        </article>
        <article className="stat-card">
          <span className="stat-label">Active Runs</span>
          <strong>{runs.filter((item) => !["completed", "destroyed"].includes(item.state)).length}</strong>
        </article>
        <article className="stat-card">
          <span className="stat-label">Bundles</span>
          <strong>{bundles.length}</strong>
        </article>
      </div>

      <div className="panel-grid">
        <section className="panel">
          <div className="panel-header">
            <h2>Feed health</h2>
            <span>{overview?.sources.length ?? 0} sources</span>
          </div>
          <div className="stack-list">
            {(overview?.sources ?? []).map((source) => (
              <article className="line-card" key={source.feed_key}>
                <div>
                  <strong>{source.display_name}</strong>
                  <p>{source.last_synced_at ? `Last sync ${new Date(source.last_synced_at).toLocaleString()}` : "No sync yet"}</p>
                </div>
                <span className={`status-pill ${source.is_stale ? "status-danger" : "status-good"}`}>
                  {source.is_stale ? "stale" : source.status}
                </span>
              </article>
            ))}
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2>Recent runs</h2>
            <span>{runs.length} shown</span>
          </div>
          <div className="stack-list">
            {runs.map((run) => (
              <article className="line-card" key={run.id}>
                <div>
                  <strong>Run #{run.id}</strong>
                  <p>{run.guest_image ?? "No image recorded"}</p>
                </div>
                <span className="status-pill">{run.state}</span>
              </article>
            ))}
            {!runs.length ? <div className="empty-panel">No runs have been launched yet.</div> : null}
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="panel-header">
          <h2>Recent bundle exports</h2>
          <span>{bundles.length} shown</span>
        </div>
        <div className="stack-list">
          {bundles.map((bundle) => (
            <article className="line-card" key={bundle.id}>
              <div>
                <strong>{bundle.title}</strong>
                <p>{bundle.bundle_type} for run #{bundle.run_id}</p>
              </div>
              <a className="ghost-button" href={bundle.download_url}>
                Download
              </a>
            </article>
          ))}
          {!bundles.length ? <div className="empty-panel">No disclosure bundles exported yet.</div> : null}
        </div>
      </section>
    </section>
  );
}
