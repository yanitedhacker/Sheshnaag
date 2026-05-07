import { useEffect, useState } from "react";
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

  return (
    <section className="page-shell">
      <header className="page-header">
        <h1>Worker Fleet</h1>
        <p>Sandbox workers enrolled to this control plane (V5).</p>
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
              <td>{w.capability_flags.join(", ") || "—"}</td>
              <td><code title={w.cert_fingerprint}>{w.cert_fingerprint.slice(0, 16)}…</code></td>
              <td>{formatTimestamp(w.last_heartbeat)}</td>
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
