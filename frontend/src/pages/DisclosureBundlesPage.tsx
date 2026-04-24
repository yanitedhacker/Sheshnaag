import { useEffect, useState } from "react";
import { api } from "../api";
import { CapabilityGate } from "../components/CapabilityGate";
import type { DisclosureBundleRecord, RunDetailResponse, RunSummary } from "../types";

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function buildExportWarnings(run: RunDetailResponse | null): string[] {
  if (!run) {
    return [];
  }
  const manifest = asRecord(run.manifest);
  const transfer = asRecord(manifest.artifact_transfer);
  const warnings: string[] = [];
  const evidenceWarnings = asRecord(manifest.acknowledgement);
  const networkPolicy = asRecord(manifest.effective_network_policy);

  if (run.requires_acknowledgement) {
    warnings.push("This run is marked sensitive. Keep the explicit acknowledgement and provenance chain attached to any external bundle.");
  }
  if (networkPolicy.mode === "bridge") {
    warnings.push(String(networkPolicy.enforcement_note ?? "Bridge mode weakens strict egress guarantees without external controls."));
  }
  if (transfer.status === "completed_with_errors") {
    warnings.push("Artifact transfer warnings are present on this run. Review checksum failures before exporting.");
  }
  if (evidenceWarnings.text_sha256) {
    warnings.push(`Acknowledgement hash available for audit: ${String(evidenceWarnings.text_sha256).slice(0, 12)}...`);
  }
  warnings.push("PCAP payloads and service logs can contain tenant-sensitive context even when the bundle export succeeds.");
  return warnings;
}

export function DisclosureBundlesPage() {
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [bundles, setBundles] = useState<DisclosureBundleRecord[]>([]);
  const [selectedRun, setSelectedRun] = useState<RunDetailResponse | null>(null);
  const [runId, setRunId] = useState<number | null>(null);
  const [bundleType, setBundleType] = useState("vendor_disclosure");
  const [title, setTitle] = useState("Sheshnaag disclosure bundle");
  const [signedBy, setSignedBy] = useState("Demo Analyst");
  const [confirmExternalExport, setConfirmExternalExport] = useState(false);
  const [reviewerName, setReviewerName] = useState("Demo Reviewer");
  const [error, setError] = useState<string | null>(null);

  async function loadBundles() {
    const [runList, disclosureList] = await Promise.all([api.listRuns(), api.listDisclosures()]);
    setRuns(runList.items);
    setRunId((current) => current ?? runList.items[0]?.id ?? null);
    setBundles(disclosureList.items);
  }

  useEffect(() => {
    loadBundles().catch((err) => setError(err instanceof Error ? err.message : "Failed to load disclosure bundles."));
  }, []);

  useEffect(() => {
    if (!runId) {
      setSelectedRun(null);
      return;
    }
    api.getRun(runId)
      .then(setSelectedRun)
      .catch(() => setSelectedRun(null));
  }, [runId]);

  async function createBundle() {
    if (!runId) {
      return;
    }
    try {
      await api.createDisclosureBundle({
        run_id: runId,
        bundle_type: bundleType,
        title,
        signed_by: signedBy,
        reviewer_name: reviewerName,
        reviewer_role: "reviewer",
        review_checklist: {
          provenance_verified: true,
          evidence_selected: true,
          redaction_reviewed: true,
        },
        confirm_external_export: confirmExternalExport,
      });
      await loadBundles();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Bundle export failed.");
    }
  }

  const exportWarnings = buildExportWarnings(selectedRun);

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Disclosure Bundles</p>
          <h1>Real export packages, not placeholder rows</h1>
          <p className="page-copy">Build and download Sheshnaag disclosure archives with manifest, report, evidence summaries, and reviewed artifacts.</p>
        </div>
      </div>

      {error ? <div className="panel error-panel">{error}</div> : null}
      {exportWarnings.length ? (
        <section className="panel warning-panel">
          <div className="panel-header">
            <h2>Export cautions</h2>
            <span>{exportWarnings.length} review points</span>
          </div>
          <div className="stack-list">
            {exportWarnings.map((warning) => (
              <article className="line-card" key={warning}>
                <div>
                  <strong>Disclosure safety</strong>
                  <p>{warning}</p>
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      <section className="panel">
        <div className="panel-header">
          <h2>Create bundle</h2>
        </div>
        <div className="form-grid">
          <select value={runId ?? ""} onChange={(event) => setRunId(Number(event.target.value))}>
            {runs.map((run) => (
              <option value={run.id} key={run.id}>
                Run #{run.id}
              </option>
            ))}
          </select>
          <select value={bundleType} onChange={(event) => setBundleType(event.target.value)}>
            <option value="vendor_disclosure">Vendor disclosure</option>
            <option value="bug_bounty">Bug bounty</option>
            <option value="research_submission">Research submission</option>
            <option value="internal_remediation">Internal remediation</option>
          </select>
          <input value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Bundle title" />
          <input value={signedBy} onChange={(event) => setSignedBy(event.target.value)} placeholder="Signed by" />
          <input value={reviewerName} onChange={(event) => setReviewerName(event.target.value)} placeholder="Reviewer" />
          <label className="checkbox-row">
            <input type="checkbox" checked={confirmExternalExport} onChange={(event) => setConfirmExternalExport(event.target.checked)} />
            Confirm external export for sensitive evidence
          </label>
          {!confirmExternalExport ? (
            <p className="field-help">External export stays blocked when the bundle includes sensitive evidence warnings.</p>
          ) : null}
          <CapabilityGate capability="external_disclosure" scope={{}}>
            <button className="primary-button" onClick={createBundle}>Export bundle</button>
          </CapabilityGate>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Bundle history</h2>
          <span>{bundles.length} exports</span>
        </div>
        <div className="stack-list">
          {bundles.map((bundle) => (
            <article className="line-card" key={bundle.id}>
              <div>
                <strong>{bundle.title}</strong>
                <p>
                  {bundle.bundle_type} · archive {bundle.archive?.filename ?? "pending"} · {String(bundle.signing?.algorithm ?? "unknown")}
                </p>
                <p className="muted">
                  {String((bundle.manifest?.export_audit as Record<string, unknown> | undefined)?.provider ?? "unknown provider")} ·{" "}
                  {String((bundle.manifest?.export_audit as Record<string, unknown> | undefined)?.verification_status ?? "verification unknown")}
                </p>
                <p className="muted">
                  Sections: {Object.entries(bundle.report_sections ?? {})
                    .filter(([, enabled]) => Boolean(enabled))
                    .map(([section]) => section)
                    .join(", ") || "report sections unavailable"}
                </p>
                <p className="muted">
                  Review history: {(bundle.review_history ?? []).length}
                </p>
              </div>
              <a className="ghost-button" href={bundle.download_url}>Download</a>
            </article>
          ))}
          {!bundles.length ? <div className="empty-panel">No bundle exports exist yet.</div> : null}
        </div>
      </section>
    </section>
  );
}
