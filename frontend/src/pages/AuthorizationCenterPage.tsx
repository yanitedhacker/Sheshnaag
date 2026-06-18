import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { useCurrentRole } from "../hooks/useCurrentRole";
import type { AuthorizationArtifact, AuthorizationChainRootResponse, AuthorizationChainVerifyResponse } from "../types";

type CapabilityMeta = {
  name: string;
  review_kind: string;
  requires_engagement_doc: boolean;
  requester_roles: string[] | null;
};

function parseScope(scopeText: string): Record<string, unknown> {
  if (!scopeText.trim()) {
    return {};
  }
  return JSON.parse(scopeText) as Record<string, unknown>;
}

function rolesPermitted(meta: CapabilityMeta | undefined, roles: string[]): boolean {
  if (!meta) return false;
  if (!meta.requester_roles?.length) return true;
  return roles.some((r) => meta.requester_roles!.includes(r));
}

function requiredReviewers(reviewKind: string): number {
  return reviewKind === "single" ? 1 : 2;
}

export function AuthorizationCenterPage() {
  const { roles } = useCurrentRole();
  const [registry, setRegistry] = useState<CapabilityMeta[]>([]);
  const [items, setItems] = useState<AuthorizationArtifact[]>([]);
  const [capability, setCapability] = useState(
    new URLSearchParams(window.location.search).get("capability") ?? "autonomous_agent_run",
  );
  const [stateFilter, setStateFilter] = useState("");
  const [scopeText, setScopeText] = useState("{}");
  const [requester, setRequester] = useState("Demo Analyst");
  const [reason, setReason] = useState("Beta authorization request");
  const [reviewerOne, setReviewerOne] = useState("Lead Reviewer");
  const [reviewerTwo, setReviewerTwo] = useState("Security Reviewer");
  const [engagementRef, setEngagementRef] = useState("");
  const [isAdminApproved, setIsAdminApproved] = useState(false);
  const [root, setRoot] = useState<AuthorizationChainRootResponse | null>(null);
  const [verify, setVerify] = useState<AuthorizationChainVerifyResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedMeta = useMemo(
    () => registry.find((item) => item.name === capability),
    [registry, capability],
  );
  const canRequest = rolesPermitted(selectedMeta, roles);
  const needsDual = selectedMeta ? requiredReviewers(selectedMeta.review_kind) >= 2 : false;
  const needsAdmin = selectedMeta?.review_kind === "dual_plus_admin";
  const needsEngagement = Boolean(selectedMeta?.requires_engagement_doc);

  useEffect(() => {
    api
      .getCapabilityRegistry()
      .then((resp) => {
        const items = resp.items as CapabilityMeta[];
        setRegistry(items);
        if (items.length && !items.some((i) => i.name === capability)) {
          setCapability(items[0].name);
        }
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load capability registry."));
  }, []);

  async function load() {
    const [auths, chainRoot, chainVerify] = await Promise.all([
      api.listAuthorizations({ capability: capability || undefined, state: stateFilter || undefined }),
      api.getAuthorizationChainRoot(),
      api.verifyAuthorizationChain(),
    ]);
    setItems(auths.items);
    setRoot(chainRoot);
    setVerify(chainVerify);
  }

  useEffect(() => {
    load().catch((err) => setError(err instanceof Error ? err.message : "Failed to load authorization state."));
  }, [capability, stateFilter]);

  async function requestAuthorization() {
    try {
      const reviewers = [{ reviewer: reviewerOne, decision: "approve" }];
      if (needsDual) {
        reviewers.push({ reviewer: reviewerTwo, decision: "approve" });
      }
      await api.requestAuthorization({
        capability,
        scope: parseScope(scopeText),
        requester,
        reason,
        reviewers,
        requested_ttl_seconds: 3600 * 24,
        engagement_ref: engagementRef || undefined,
        is_admin_approved: needsAdmin ? isAdminApproved : false,
      });
      setError(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authorization request failed.");
    }
  }

  async function revoke(artifactId: string) {
    try {
      await api.revokeAuthorization(artifactId, { actor: requester, reason: "Revoked from Authorization Center" });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Revoke failed.");
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Authorization Center</p>
          <h1>Signed capability artifacts and audit-chain verification</h1>
          <p className="page-copy">
            Issue, inspect, and revoke scoped authorization artifacts. Quorum follows each capability&apos;s review_kind.
          </p>
        </div>
      </div>

      {error ? <div className="panel error-panel">{error}</div> : null}

      <div className="panel-grid candidate-grid">
        <section className="panel">
          <div className="panel-header">
            <h2>Request authorization</h2>
            <span className="status-pill">{capability}</span>
          </div>
          <div className="form-grid">
            <select value={capability} onChange={(event) => setCapability(event.target.value)}>
              {registry.map((item) => (
                <option key={item.name} value={item.name}>
                  {item.name} ({item.review_kind})
                </option>
              ))}
            </select>
            <input value={requester} onChange={(event) => setRequester(event.target.value)} placeholder="Requester" />
            <input value={reviewerOne} onChange={(event) => setReviewerOne(event.target.value)} placeholder="Reviewer 1" />
            {needsDual ? (
              <input value={reviewerTwo} onChange={(event) => setReviewerTwo(event.target.value)} placeholder="Reviewer 2" />
            ) : null}
            {needsEngagement ? (
              <input value={engagementRef} onChange={(event) => setEngagementRef(event.target.value)} placeholder="Engagement digest or URL" />
            ) : null}
            {needsAdmin ? (
              <label className="checkbox-row">
                <input type="checkbox" checked={isAdminApproved} onChange={(event) => setIsAdminApproved(event.target.checked)} />
                Admin co-signature recorded
              </label>
            ) : null}
            <textarea value={scopeText} onChange={(event) => setScopeText(event.target.value)} rows={4} />
            <textarea value={reason} onChange={(event) => setReason(event.target.value)} rows={4} />
            {!canRequest ? (
              <p className="muted">Your role cannot request this capability ({roles.join(", ") || "none"}).</p>
            ) : null}
            <button className="primary-button" disabled={!canRequest} onClick={() => void requestAuthorization()}>
              Issue artifact
            </button>
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2>Chain verification</h2>
            <span className={`status-pill${verify?.ok ? " status-good" : " status-danger"}`}>{verify?.reason ?? "unknown"}</span>
          </div>
          <div className="stack-list">
            <article className="line-card">
              <div>
                <strong>Current root</strong>
                <p>{root?.entry_hash ?? "No root available"}</p>
              </div>
              <span>idx {root?.idx ?? "n/a"}</span>
            </article>
            <article className="line-card">
              <div>
                <strong>Verification</strong>
                <p>Last verified index {verify?.last_verified_idx ?? "n/a"}</p>
              </div>
              <span>{verify?.ok ? "ok" : "attention"}</span>
            </article>
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="panel-header">
          <h2>Artifacts</h2>
          <div className="toolbar">
            <select value={stateFilter} onChange={(event) => setStateFilter(event.target.value)}>
              <option value="">All states</option>
              <option value="active">Active</option>
              <option value="revoked">Revoked</option>
            </select>
          </div>
        </div>
        <div className="stack-list">
          {items.map((item) => (
            <article className="line-card stacked-card" key={item.artifact_id}>
              <div>
                <strong>{item.artifact_id}</strong>
                <p>{item.capability} · expires {item.expires_at ? new Date(item.expires_at).toLocaleString() : "n/a"}</p>
                <p className="muted">
                  Reviewers {(item.reviewers ?? []).map((reviewer) => String(reviewer.reviewer)).join(", ") || "none"}
                </p>
                <pre className="code-card">{JSON.stringify(item.scope, null, 2)}</pre>
              </div>
              <div className="button-row">
                <button className="ghost-button" onClick={() => void api.approveAuthorization(item.artifact_id, { reviewer: reviewerOne })}>
                  Check approval
                </button>
                <button className="primary-button" disabled={Boolean(item.revoked_at)} onClick={() => void revoke(item.artifact_id)}>
                  Revoke
                </button>
              </div>
            </article>
          ))}
          {!items.length ? <div className="empty-panel">No authorization artifacts match this filter.</div> : null}
        </div>
      </section>
    </section>
  );
}
