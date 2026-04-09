import { useEffect, useState } from "react";
import { api } from "../api";
import type { RunDetailResponse, RunSummary } from "../types";

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String) : [];
}

function buildSafetyWarnings(detail: RunDetailResponse): string[] {
  const warnings: string[] = [];
  const manifest = asRecord(detail.manifest);
  const acknowledgement = asRecord(manifest.acknowledgement);
  const effectivePolicy = asRecord(manifest.effective_network_policy);
  const artifactTransfer = asRecord(manifest.artifact_transfer);
  const mounts = Array.isArray(manifest.mounts) ? manifest.mounts : [];
  const collectors = asStringArray(manifest.collectors);
  const allowEgressHosts = asStringArray(effectivePolicy.allow_egress_hosts);

  if (detail.requires_acknowledgement) {
    if (detail.acknowledged_by && detail.acknowledged_at) {
      warnings.push(
        `Sensitive run acknowledged by ${detail.acknowledged_by} at ${new Date(detail.acknowledged_at).toLocaleString()}.`,
      );
    } else {
      warnings.push("Sensitive run requires explicit analyst acknowledgement before execution.");
    }
  }

  if (effectivePolicy.mode === "bridge") {
    warnings.push(String(effectivePolicy.enforcement_note ?? "Bridge networking requires external egress enforcement."));
  }

  if (allowEgressHosts.length > 0 && !collectors.includes("network_metadata")) {
    warnings.push("Egress is enabled but the network metadata collector is absent, so outbound activity correlation is weaker.");
  }

  if (collectors.includes("tracee_events") && !collectors.includes("process_tree")) {
    warnings.push("Tracee is enabled without process_tree baseline data, which can make runtime evidence harder to interpret.");
  }

  if (artifactTransfer.status === "completed_with_errors") {
    warnings.push("One or more artifact inputs failed checksum or copy verification. Review the transfer event before trusting the run.");
  } else if (artifactTransfer.status === "pending_workspace") {
    warnings.push("Artifact inputs are queued but have not been copied yet because the provider workspace is not allocated.");
  }

  if (mounts.some((mount) => asRecord(mount).read_only === false)) {
    warnings.push("This run uses a writable host mount. Confirm the recorded mount approval before sharing evidence externally.");
  }

  if (acknowledgement.text_sha256) {
    warnings.push(`Acknowledgement hash recorded: ${String(acknowledgement.text_sha256).slice(0, 12)}...`);
  }

  return warnings;
}

export function RunConsolePage() {
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);
  const [detail, setDetail] = useState<RunDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function loadRuns() {
    const data = await api.listRuns();
    setRuns(data.items);
    setSelectedRunId((current) => current ?? data.items[0]?.id ?? null);
  }

  async function loadDetail(runId: number) {
    const data = await api.getRun(runId);
    setDetail(data);
  }

  useEffect(() => {
    loadRuns().catch((err) => setError(err instanceof Error ? err.message : "Failed to load runs."));
  }, []);

  useEffect(() => {
    if (!selectedRunId) {
      return;
    }
    loadDetail(selectedRunId).catch((err) => setError(err instanceof Error ? err.message : "Failed to load run detail."));
  }, [selectedRunId]);

  useEffect(() => {
    if (!detail || !["running", "booting", "ready", "unhealthy"].includes(detail.state)) {
      return;
    }
    const timer = window.setInterval(() => {
      api.getRunHealth(detail.id)
        .then(() => api.getRun(detail.id))
        .then(setDetail)
        .catch(() => null);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [detail]);

  async function act(action: "stop" | "teardown" | "destroy") {
    if (!detail) {
      return;
    }
    try {
      if (action === "stop") {
        await api.stopRun(detail.id, {});
      } else if (action === "teardown") {
        await api.teardownRun(detail.id, {});
      } else {
        await api.destroyRun(detail.id, {});
      }
      await loadRuns();
      await loadDetail(detail.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Run action failed.");
    }
  }

  const safetyWarnings = detail ? buildSafetyWarnings(detail) : [];

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Run Console</p>
          <h1>Lifecycle, health, and transcript tracking</h1>
          <p className="page-copy">Monitor live or simulated validation runs and step into the evidence timeline without raw API calls.</p>
        </div>
      </div>

      {error ? <div className="panel error-panel">{error}</div> : null}
      {detail && safetyWarnings.length ? (
        <section className="panel warning-panel">
          <div className="panel-header">
            <h2>Safety posture</h2>
            <span>{safetyWarnings.length} checks</span>
          </div>
          <div className="stack-list">
            {safetyWarnings.map((warning) => (
              <article className="line-card" key={warning}>
                <div>
                  <strong>Operator warning</strong>
                  <p>{warning}</p>
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      <div className="panel-grid candidate-grid">
        <section className="panel">
          <div className="panel-header">
            <h2>Runs</h2>
            <span>{runs.length} total</span>
          </div>
          <div className="data-table">
            {runs.map((run) => (
              <button
                type="button"
                key={run.id}
                className={`table-row-button${selectedRunId === run.id ? " is-selected" : ""}`}
                onClick={() => setSelectedRunId(run.id)}
              >
                <strong>Run #{run.id}</strong>
                <span>{run.launch_mode}</span>
                <span>{run.guest_image ?? "No image"}</span>
                <span>{run.state}</span>
              </button>
            ))}
            {!runs.length ? <div className="empty-panel">No runs recorded yet.</div> : null}
          </div>
        </section>

        <section className="panel detail-panel">
          <div className="panel-header">
            <h2>{detail ? `Run #${detail.id}` : "Select a run"}</h2>
            <span className="status-pill">{detail?.state ?? "idle"}</span>
          </div>
          {detail ? (
            <>
              <div className="stat-inline-grid">
                <article><span>Mode</span><strong>{detail.launch_mode}</strong></article>
                <article><span>Image</span><strong>{detail.guest_image ?? "n/a"}</strong></article>
                <article><span>Findings</span><strong>{detail.runtime_findings_summary.count}</strong></article>
              </div>
              <div className="button-row">
                <button className="ghost-button" onClick={() => act("stop")}>Stop</button>
                <button className="ghost-button" onClick={() => act("teardown")}>Teardown</button>
                <button className="primary-button" onClick={() => act("destroy")}>Destroy</button>
              </div>
              <div className="panel-subsection">
                <h3>Event timeline</h3>
                <div className="stack-list">
                  {detail.timeline.map((event, index) => (
                    <article className="line-card" key={`${event.event_type}-${index}`}>
                      <div>
                        <strong>{event.event_type}</strong>
                        <p>{event.message}</p>
                      </div>
                      <span>{event.created_at ? new Date(event.created_at).toLocaleString() : "n/a"}</span>
                    </article>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="empty-panel">Choose a run to inspect health and lifecycle events.</div>
          )}
        </section>
      </div>
    </section>
  );
}
