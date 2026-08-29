import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { useCurrentRole } from "../hooks/useCurrentRole";
import type {
  AuthorizationArtifact,
  AuthorizationChainRootResponse,
  AuthorizationChainVerifyResponse,
  AuthorizationRequestRecord,
} from "../types";

type CapabilityMeta = {
  name: string;
  review_kind: string;
  requires_engagement_doc: boolean;
  requester_roles: string[] | null;
};

const DEFAULT_ACTION_ARGUMENTS = JSON.stringify(
  {
    tenant_id: 1,
    case_id: null,
    goal: "Review this exact case.",
    max_steps: 3,
  },
  null,
  2,
);

function parseActionArguments(text: string): Record<string, unknown> {
  const parsed = JSON.parse(text) as unknown;
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error("Action arguments must be a JSON object.");
  }
  return parsed as Record<string, unknown>;
}

function rolesPermitted(meta: CapabilityMeta | undefined, roles: string[]): boolean {
  if (!meta) return false;
  if (!meta.requester_roles?.length) return true;
  return roles.some((r) => meta.requester_roles!.includes(r));
}

export function AuthorizationCenterPage() {
  const { roles } = useCurrentRole();
  const [registry, setRegistry] = useState<CapabilityMeta[]>([]);
  const [artifacts, setArtifacts] = useState<AuthorizationArtifact[]>([]);
  const [requests, setRequests] = useState<AuthorizationRequestRecord[]>([]);
  const [capability, setCapability] = useState(
    new URLSearchParams(window.location.search).get("capability") ?? "autonomous_agent_run",
  );
  const [artifactStateFilter, setArtifactStateFilter] = useState("");
  const [requestStateFilter, setRequestStateFilter] = useState("");
  const [actionArgumentsText, setActionArgumentsText] = useState(DEFAULT_ACTION_ARGUMENTS);
  const [requester, setRequester] = useState("Demo Analyst");
  const [reason, setReason] = useState("Approve one exact beta action.");
  const [engagementRef, setEngagementRef] = useState("");
  const [decisionNote, setDecisionNote] = useState("Exact action and scope verified.");
  const [root, setRoot] = useState<AuthorizationChainRootResponse | null>(null);
  const [verify, setVerify] = useState<AuthorizationChainVerifyResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedMeta = useMemo(
    () => registry.find((item) => item.name === capability),
    [registry, capability],
  );
  const canRequest = rolesPermitted(selectedMeta, roles);
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
    const [authorizationArtifacts, authorizationRequests, chainRoot, chainVerify] = await Promise.all([
      api.listAuthorizations({
        capability: capability || undefined,
        state: artifactStateFilter || undefined,
      }),
      api.listAuthorizationRequests({
        capability: capability || undefined,
        state: requestStateFilter || undefined,
      }),
      api.getAuthorizationChainRoot(),
      api.verifyAuthorizationChain(),
    ]);
    setArtifacts(authorizationArtifacts.items);
    setRequests(authorizationRequests.items);
    setRoot(chainRoot);
    setVerify(chainVerify);
  }

  useEffect(() => {
    load().catch((loadError) =>
      setError(loadError instanceof Error ? loadError.message : "Failed to load authorization state."),
    );
  }, [capability, artifactStateFilter, requestStateFilter]);

  async function requestAuthorization() {
    try {
      await api.requestAuthorization({
        capability,
        action: capability,
        action_arguments: parseActionArguments(actionArgumentsText),
        requester,
        reason,
        requested_ttl_seconds: 3600 * 24,
        engagement_ref: engagementRef || undefined,
      });
      setError(null);
      await load();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Authorization request failed.");
    }
  }

  async function decide(requestId: string, decision: "approve" | "reject") {
    try {
      await api.decideAuthorizationRequest(requestId, {
        decision,
        note: decisionNote || undefined,
      });
      setError(null);
      await load();
    } catch (decisionError) {
      setError(decisionError instanceof Error ? decisionError.message : "Authorization decision failed.");
    }
  }

  async function revoke(artifactId: string) {
    try {
      await api.revokeAuthorization(artifactId, {
        actor: requester,
        reason: "Revoked from Authorization Center",
      });
      setError(null);
      await load();
    } catch (revokeError) {
      setError(revokeError instanceof Error ? revokeError.message : "Revoke failed.");
    }
  }

  return (
    <section className="operator-page">
      <div className="page-intro">
        <div>
          <p className="eyebrow">Authorization Center</p>
          <h1>Independent exact-action approvals</h1>
          <p className="page-copy">
            Request one action, review its server-derived digest, and issue a signed artifact only after the server-enforced independent quorum approves it.
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
            <input value={requester} onChange={(event) => setRequester(event.target.value)} placeholder="Requester fallback for local development" />
            {needsEngagement ? (
              <input value={engagementRef} onChange={(event) => setEngagementRef(event.target.value)} placeholder="Engagement digest or URL" />
            ) : null}
            <label>
              Exact action arguments
              <textarea value={actionArgumentsText} onChange={(event) => setActionArgumentsText(event.target.value)} rows={8} />
            </label>
            <label>
              Reason
              <textarea value={reason} onChange={(event) => setReason(event.target.value)} rows={4} />
            </label>
            {!canRequest ? (
              <p className="muted">Your role cannot request this capability ({roles.join(", ") || "none"}).</p>
            ) : null}
            <button className="primary-button" disabled={!canRequest} onClick={() => void requestAuthorization()}>
              Submit request
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
          <h2>Approval requests</h2>
          <div className="toolbar">
            <select value={requestStateFilter} onChange={(event) => setRequestStateFilter(event.target.value)}>
              <option value="">All states</option>
              <option value="pending">Pending</option>
              <option value="issued">Issued</option>
              <option value="rejected">Rejected</option>
              <option value="expired">Expired</option>
            </select>
          </div>
        </div>
        <label className="form-grid">
          Reviewer note
          <input value={decisionNote} onChange={(event) => setDecisionNote(event.target.value)} />
        </label>
        <div className="stack-list">
          {requests.map((item) => (
            <article className="line-card stacked-card" key={item.request_id}>
              <div>
                <strong>{item.request_id}</strong>
                <p>{item.capability} · {item.status} · requester {item.requester}</p>
                <p className="muted">
                  {item.decisions.length}/{item.required_approvals} approvals
                  {item.requires_admin_approval ? " · lab lead required" : ""}
                </p>
                <p className="muted">Digest {item.action_digest}</p>
                <pre className="code-card">{JSON.stringify(item.scope, null, 2)}</pre>
                {item.decisions.map((decision) => (
                  <p className="muted" key={`${item.request_id}-${decision.reviewer}`}>
                    {decision.reviewer}: {decision.decision}
                  </p>
                ))}
              </div>
              {item.status === "pending" ? (
                <div className="button-row">
                  <button className="ghost-button" onClick={() => void decide(item.request_id, "reject")}>Reject</button>
                  <button className="primary-button" onClick={() => void decide(item.request_id, "approve")}>Approve exact action</button>
                </div>
              ) : null}
            </article>
          ))}
          {!requests.length ? <div className="empty-panel">No authorization requests match this filter.</div> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Issued artifacts</h2>
          <div className="toolbar">
            <select value={artifactStateFilter} onChange={(event) => setArtifactStateFilter(event.target.value)}>
              <option value="">All states</option>
              <option value="active">Active</option>
              <option value="revoked">Revoked</option>
            </select>
          </div>
        </div>
        <div className="stack-list">
          {artifacts.map((item) => (
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
                <button className="primary-button" disabled={Boolean(item.revoked_at)} onClick={() => void revoke(item.artifact_id)}>
                  Revoke
                </button>
              </div>
            </article>
          ))}
          {!artifacts.length ? <div className="empty-panel">No authorization artifacts match this filter.</div> : null}
        </div>
      </section>
    </section>
  );
}
