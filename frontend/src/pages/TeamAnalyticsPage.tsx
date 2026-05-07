import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type {
  AnalyticsSummaryResponse,
  AttackDriftResponse,
  CapabilityUsageResponse,
} from "../types";

const WINDOW_OPTIONS: ReadonlyArray<{ label: string; days: number }> = [
  { label: "7 days", days: 7 },
  { label: "30 days", days: 30 },
  { label: "90 days", days: 90 },
];

function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${seconds.toFixed(0)}s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

function maxOf(buckets: Record<string, number[]>): number {
  let m = 0;
  for (const arr of Object.values(buckets)) {
    for (const v of arr) m = Math.max(m, v);
  }
  return m;
}

function intensity(value: number, max: number): string {
  if (max <= 0) return "rgba(64, 96, 192, 0)";
  const ratio = Math.min(value / max, 1);
  return `rgba(64, 96, 192, ${0.05 + ratio * 0.85})`;
}

export function TeamAnalyticsPage() {
  const [windowDays, setWindowDays] = useState(30);
  const [summary, setSummary] = useState<AnalyticsSummaryResponse | null>(null);
  const [drift, setDrift] = useState<AttackDriftResponse | null>(null);
  const [capUsage, setCapUsage] = useState<CapabilityUsageResponse | null>(
    null
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      api.analyticsSummary(windowDays),
      api.analyticsAttackDrift(windowDays),
      api.analyticsCapabilityUsage(windowDays),
    ])
      .then(([s, d, c]) => {
        if (cancelled) return;
        setSummary(s);
        setDrift(d);
        setCapUsage(c);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [windowDays]);

  const queueAgingMax = useMemo(
    () => (summary ? maxOf(summary.queue_aging.state_buckets) : 0),
    [summary]
  );

  const capabilityActors = useMemo(() => {
    if (!capUsage) return [];
    return Object.entries(capUsage.by_actor)
      .map(([actor, counts]) => {
        const total = Object.values(counts).reduce((a, b) => a + b, 0);
        return { actor, counts, total };
      })
      .sort((a, b) => b.total - a.total)
      .slice(0, 12);
  }, [capUsage]);

  const capabilityList = useMemo(() => {
    if (!capUsage) return [];
    return Object.entries(capUsage.by_capability)
      .sort((a, b) => b[1] - a[1])
      .map(([k]) => k);
  }, [capUsage]);

  return (
    <section className="page-shell">
      <header className="page-header">
        <h1>Team analytics</h1>
        <p>
          Lifecycle, review-latency, ATT&amp;CK drift, capability usage, and
          queue-aging telemetry across the active workspace (V5 W3a).
        </p>
      </header>

      <div
        className="action-bar"
        style={{ display: "flex", gap: "0.5rem", margin: "1rem 0" }}
      >
        <span style={{ alignSelf: "center" }}>Window:</span>
        {WINDOW_OPTIONS.map((opt) => (
          <button
            key={opt.days}
            className={
              opt.days === windowDays ? "primary-button" : "ghost-button"
            }
            onClick={() => setWindowDays(opt.days)}
          >
            {opt.label}
          </button>
        ))}
      </div>

      {error ? (
        <div
          className="callout callout-danger"
          style={{ marginBottom: "1rem" }}
        >
          {error}
        </div>
      ) : null}

      {loading && !summary ? (
        <p style={{ opacity: 0.7 }}>Loading…</p>
      ) : null}

      {summary ? (
        <>
          <div
            className="kpi-grid"
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
              gap: "0.75rem",
              marginBottom: "1.5rem",
            }}
          >
            <KpiCard
              title="Cases closed"
              big={String(summary.mttr.sample_count)}
              small={`window ${summary.window_days}d`}
            />
            <KpiCard
              title="MTTR (median)"
              big={formatDuration(summary.mttr.overall_p50_seconds)}
              small={`p95 ${formatDuration(summary.mttr.overall_p95_seconds)}`}
            />
            <KpiCard
              title="Review latency (median)"
              big={formatDuration(summary.review_latency.overall_p50_seconds)}
              small={`p95 ${formatDuration(
                summary.review_latency.overall_p95_seconds
              )}`}
            />
            <KpiCard
              title="AI sessions"
              big={String(
                Object.values(summary.ai_session_volume).reduce(
                  (a, b) => a + b,
                  0
                )
              )}
              small={Object.entries(summary.ai_session_volume)
                .map(([k, v]) => `${k}: ${v}`)
                .join(" · ")}
            />
          </div>

          <h2>Queue aging</h2>
          <table className="data-table" style={{ marginBottom: "1.5rem" }}>
            <thead>
              <tr>
                <th>State</th>
                {summary.queue_aging.bucket_labels.map((label) => (
                  <th key={label}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {Object.entries(summary.queue_aging.state_buckets).map(
                ([state, buckets]) => (
                  <tr key={state}>
                    <th scope="row">{state}</th>
                    {buckets.map((count, idx) => (
                      <td
                        key={idx}
                        style={{
                          backgroundColor: intensity(count, queueAgingMax),
                          textAlign: "center",
                        }}
                      >
                        {count || ""}
                      </td>
                    ))}
                  </tr>
                )
              )}
            </tbody>
          </table>

          <h2>MTTR by analyst</h2>
          <table className="data-table" style={{ marginBottom: "1.5rem" }}>
            <thead>
              <tr>
                <th>Analyst</th>
                <th>Cases</th>
                <th>Mean</th>
                <th>p50</th>
                <th>p95</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(summary.mttr.by_analyst).length === 0 ? (
                <tr>
                  <td
                    colSpan={5}
                    style={{ textAlign: "center", opacity: 0.6, padding: "1rem" }}
                  >
                    No closed cases in window.
                  </td>
                </tr>
              ) : null}
              {Object.entries(summary.mttr.by_analyst)
                .sort((a, b) => b[1].count - a[1].count)
                .map(([actor, vals]) => (
                  <tr key={actor}>
                    <td>{actor}</td>
                    <td>{vals.count}</td>
                    <td>{formatDuration(vals.mean_seconds)}</td>
                    <td>{formatDuration(vals.p50_seconds)}</td>
                    <td>{formatDuration(vals.p95_seconds)}</td>
                  </tr>
                ))}
            </tbody>
          </table>

          <h2>Review latency by reviewer</h2>
          <table className="data-table" style={{ marginBottom: "1.5rem" }}>
            <thead>
              <tr>
                <th>Reviewer</th>
                <th>Decisions</th>
                <th>Mean</th>
                <th>p50</th>
                <th>p95</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(summary.review_latency.by_reviewer).length ===
              0 ? (
                <tr>
                  <td
                    colSpan={5}
                    style={{ textAlign: "center", opacity: 0.6, padding: "1rem" }}
                  >
                    No review decisions in window.
                  </td>
                </tr>
              ) : null}
              {Object.entries(summary.review_latency.by_reviewer)
                .sort((a, b) => b[1].count - a[1].count)
                .map(([actor, vals]) => (
                  <tr key={actor}>
                    <td>{actor}</td>
                    <td>{vals.count}</td>
                    <td>{formatDuration(vals.mean_seconds)}</td>
                    <td>{formatDuration(vals.p50_seconds)}</td>
                    <td>{formatDuration(vals.p95_seconds)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </>
      ) : null}

      {drift ? (
        <>
          <h2>ATT&amp;CK coverage drift</h2>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "1rem",
              marginBottom: "1.5rem",
            }}
          >
            <div className="callout callout-info">
              <strong>New in current window</strong>
              <p style={{ margin: "0.25rem 0 0.5rem" }}>
                {drift.new_in_current.length} technique
                {drift.new_in_current.length === 1 ? "" : "s"} appeared this
                window.
              </p>
              <code style={{ display: "block", overflowX: "auto" }}>
                {drift.new_in_current.length > 0
                  ? drift.new_in_current.join(", ")
                  : "—"}
              </code>
            </div>
            <div className="callout callout-warning">
              <strong>Dropped from prior window</strong>
              <p style={{ margin: "0.25rem 0 0.5rem" }}>
                {drift.dropped_from_prior.length} technique
                {drift.dropped_from_prior.length === 1 ? "" : "s"} no longer
                observed.
              </p>
              <code style={{ display: "block", overflowX: "auto" }}>
                {drift.dropped_from_prior.length > 0
                  ? drift.dropped_from_prior.join(", ")
                  : "—"}
              </code>
            </div>
          </div>
        </>
      ) : null}

      {capUsage ? (
        <>
          <h2>Capability usage by actor</h2>
          <p style={{ opacity: 0.7, marginBottom: "0.5rem" }}>
            {capUsage.distinct_actors} distinct actor
            {capUsage.distinct_actors === 1 ? "" : "s"} exercised{" "}
            {Object.keys(capUsage.by_capability).length} capabilit
            {Object.keys(capUsage.by_capability).length === 1 ? "y" : "ies"} in
            window.
          </p>
          {capabilityActors.length === 0 ? (
            <p style={{ opacity: 0.6 }}>No capability usage in window.</p>
          ) : (
            <table className="data-table" style={{ marginBottom: "1.5rem" }}>
              <thead>
                <tr>
                  <th>Actor</th>
                  {capabilityList.map((cap) => (
                    <th key={cap}>{cap}</th>
                  ))}
                  <th>Total</th>
                </tr>
              </thead>
              <tbody>
                {capabilityActors.map(({ actor, counts, total }) => (
                  <tr key={actor}>
                    <td>{actor}</td>
                    {capabilityList.map((cap) => (
                      <td key={cap} style={{ textAlign: "center" }}>
                        {counts[cap] || ""}
                      </td>
                    ))}
                    <td style={{ fontWeight: 600 }}>{total}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      ) : null}
    </section>
  );
}

function KpiCard({
  title,
  big,
  small,
}: {
  title: string;
  big: string;
  small: string;
}) {
  return (
    <div
      className="kpi-card"
      style={{
        border: "1px solid var(--border, #ddd)",
        borderRadius: "0.5rem",
        padding: "0.75rem 1rem",
        background: "var(--surface, #fff)",
      }}
    >
      <div style={{ fontSize: "0.85rem", opacity: 0.7 }}>{title}</div>
      <div style={{ fontSize: "1.5rem", fontWeight: 600, marginTop: "0.25rem" }}>
        {big}
      </div>
      <div style={{ fontSize: "0.75rem", opacity: 0.6, marginTop: "0.25rem" }}>
        {small}
      </div>
    </div>
  );
}
