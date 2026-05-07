import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { WorkerSummary, EnrollmentTokenResponse } from "../types";

function formatTimestamp(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

function stateClass(state: string): string {
  if (state === "online") return "status-pill status-good";
  if (state === "draining") return "status-pill status-warning";
  return "status-pill status-danger";
}

function CapabilityChips({ flags }: { flags: string[] }) {
  if (!flags.length) return <span style={{ opacity: 0.5 }}>—</span>;
  return (
    <span style={{ display: "inline-flex", gap: "0.25rem", flexWrap: "wrap" }}>
      {flags.map((flag) => (
        <code
          key={flag}
          style={{
            padding: "0.1rem 0.4rem",
            borderRadius: "0.25rem",
            background: "rgba(64, 96, 192, 0.15)",
            fontSize: "0.75rem",
          }}
        >
          {flag}
        </code>
      ))}
    </span>
  );
}

function heartbeatFreshness(iso: string | null): {
  label: string;
  fresh: boolean;
} {
  if (!iso) return { label: "never", fresh: false };
  const ageSeconds = (Date.now() - new Date(iso).getTime()) / 1000;
  if (ageSeconds < 60) return { label: `${ageSeconds.toFixed(0)}s ago`, fresh: true };
  if (ageSeconds < 3600)
    return { label: `${(ageSeconds / 60).toFixed(0)}m ago`, fresh: ageSeconds < 120 };
  return { label: `${(ageSeconds / 3600).toFixed(1)}h ago`, fresh: false };
}

export function WorkerFleetPage() {
  const [workers, setWorkers] = useState<WorkerSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [enrollment, setEnrollment] = useState<EnrollmentTokenResponse | null>(null);
  const [enrollmentBusy, setEnrollmentBusy] = useState(false);

  const refresh = async () => {
    setLoading(true);
    try {
      const rows = await api.listWorkers();
      setWorkers(rows);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, 15_000);
    return () => window.clearInterval(id);
  }, []);

  const handleIssueToken = async () => {
    setEnrollmentBusy(true);
    try {
      const issued = await api.issueEnrollmentToken();
      setEnrollment(issued);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setEnrollmentBusy(false);
    }
  };

  const handleDrain = async (workerId: number) => {
    if (!window.confirm(`Drain worker ${workerId}? In-flight jobs will finish but no new jobs accepted.`)) {
      return;
    }
    try {
      await api.drainWorker(workerId);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const counts = useMemo(() => {
    const out = { online: 0, draining: 0, offline: 0 };
    for (const w of workers) {
      if (w.state === "online") out.online += 1;
      else if (w.state === "draining") out.draining += 1;
      else out.offline += 1;
    }
    return out;
  }, [workers]);

  return (
    <section className="page-shell">
      <header className="page-header">
        <h1>Worker Fleet</h1>
        <p>Sandbox workers enrolled to this control plane (V5).</p>
        <div
          style={{
            display: "flex",
            gap: "0.75rem",
            marginTop: "0.5rem",
            flexWrap: "wrap",
          }}
        >
          <span className="status-pill status-good">
            {counts.online} online
          </span>
          <span className="status-pill status-warning">
            {counts.draining} draining
          </span>
          <span className="status-pill status-danger">
            {counts.offline} offline
          </span>
        </div>
      </header>

      <div className="action-bar" style={{ display: "flex", gap: "0.75rem", margin: "1rem 0" }}>
        <button
          className="primary-button"
          onClick={handleIssueToken}
          disabled={enrollmentBusy}
        >
          {enrollmentBusy ? "Minting…" : "Issue enrollment token"}
        </button>
        <button className="ghost-button" onClick={refresh} disabled={loading}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      {enrollment ? (
        <div className="callout callout-warning" style={{ marginBottom: "1rem" }}>
          <strong>Single-use enrollment token.</strong> Copy now — it will not be shown again.
          <pre style={{ overflowX: "auto", padding: "0.5rem", marginTop: "0.5rem" }}>
            {enrollment.token}
          </pre>
          <small>Expires {new Date(enrollment.expires_at).toLocaleString()}</small>
          <details style={{ marginTop: "0.5rem" }}>
            <summary>Worker bootstrap command</summary>
            <pre style={{ overflowX: "auto", padding: "0.5rem", fontSize: "0.8rem" }}>
{`# On the worker host, after installing the sandbox-agent:
sudo /opt/sheshnaag/bin/sandbox-agent enroll \\
  --control-plane https://<this-host> \\
  --token ${enrollment.token}`}
            </pre>
          </details>
        </div>
      ) : null}

      {error ? (
        <div className="callout callout-danger" style={{ marginBottom: "1rem" }}>{error}</div>
      ) : null}

      <table className="data-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>UUID</th>
            <th>State</th>
            <th>Capabilities</th>
            <th>Cert fingerprint</th>
            <th>Last heartbeat</th>
            <th>Enrolled</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {workers.length === 0 && !loading ? (
            <tr>
              <td colSpan={8} style={{ textAlign: "center", padding: "2rem", opacity: 0.6 }}>
                No workers enrolled. Issue an enrollment token to bootstrap the first one.
              </td>
            </tr>
          ) : null}
          {workers.map((w) => (
            <tr key={w.id}>
              <td>{w.id}</td>
              <td><code>{w.worker_uuid.slice(0, 8)}…</code></td>
              <td><span className={stateClass(w.state)}>{w.state}</span></td>
              <td><CapabilityChips flags={w.capability_flags} /></td>
              <td><code title={w.cert_fingerprint}>{w.cert_fingerprint.slice(0, 16)}…</code></td>
              <td>
                <span title={formatTimestamp(w.last_heartbeat)}>
                  {(() => {
                    const f = heartbeatFreshness(w.last_heartbeat);
                    return (
                      <span
                        style={{
                          color: f.fresh ? undefined : "var(--danger, #c33)",
                          fontWeight: f.fresh ? undefined : 600,
                        }}
                      >
                        {f.label}
                      </span>
                    );
                  })()}
                </span>
              </td>
              <td>
                {formatTimestamp(w.enrolled_at)}<br />
                <small>by {w.enrolled_by}</small>
              </td>
              <td>
                {w.state !== "draining" ? (
                  <button
                    className="ghost-button danger"
                    onClick={() => handleDrain(w.id)}
                  >
                    Drain
                  </button>
                ) : (
                  <span style={{ opacity: 0.6 }}>draining</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
