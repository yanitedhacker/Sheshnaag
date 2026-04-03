import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api";

const sampleSbom = {
  metadata: {
    component: {
      "bom-ref": "svc-checkout",
      name: "checkout-service",
      type: "service",
      description: "Customer checkout entry point that depends on the payments API.",
    },
  },
  services: [
    {
      "bom-ref": "svc-checkout",
      name: "checkout-service",
      type: "service",
      description: "Customer-facing checkout workflow.",
    },
    {
      "bom-ref": "svc-payments",
      name: "payments-api",
      type: "service",
      description: "Internal payment authorization dependency.",
    },
  ],
  components: [
    {
      "bom-ref": "cmp-checkout-ui",
      type: "application",
      publisher: "acme",
      name: "checkout-ui",
      version: "3.1.0",
      purl: "pkg:generic/acme/checkout-ui@3.1.0",
      description: "Frontend package exposed through the checkout service.",
    },
    {
      "bom-ref": "cmp-payments",
      type: "application",
      publisher: "acme",
      name: "payments-api",
      version: "2.3.0",
      purl: "pkg:generic/acme/payments-api@2.3.0",
      description: "Backend API component that already maps to the demo CVE corpus.",
    },
  ],
  dependencies: [
    { ref: "svc-checkout", dependsOn: ["svc-payments"] },
  ],
};

const sampleVex = {
  "@id": "https://example.com/openvex/checkout-private",
  statements: [
    {
      vulnerability: { name: "CVE-2024-10002" },
      products: [{ "@id": "cmp-payments", name: "payments-api", version: "2.3.0" }],
      status: "under_investigation",
      justification: "The checkout private workspace still carries the vulnerable dependency while validation is ongoing.",
    },
  ],
};

export function OperationsPage() {
  const approvals = useQuery({ queryKey: ["approvals"], queryFn: api.getApprovals });
  const audit = useQuery({ queryKey: ["audit"], queryFn: api.getAudit });
  const feedback = useQuery({ queryKey: ["feedback"], queryFn: api.getFeedback });
  const tenants = useQuery({ queryKey: ["tenants"], queryFn: api.getTenants });

  const [tenantForm, setTenantForm] = useState({
    tenant_name: "Acme Private Workspace",
    tenant_slug: `acme-private-${Math.random().toString(36).slice(2, 6)}`,
    admin_email: "owner@example.com",
    admin_password: "supersecure123",
    admin_name: "Owner Example",
    description: "Private tenant created from the operations console.",
  });

  const onboard = useMutation({
    mutationFn: () => api.onboardTenant(tenantForm),
  });

  const sbomImport = useMutation({
    mutationFn: (tenantId: number) => api.importSbom({ tenant_id: tenantId, document: sampleSbom }),
  });

  const vexImport = useMutation({
    mutationFn: (tenantId: number) => api.importVex({ tenant_id: tenantId, document: sampleVex }),
  });

  const privateTenantId = onboard.data?.tenant.id;

  return (
    <section className="operations-grid">
      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Private Workspaces</p>
            <h3>Onboard a tenant and seed supply-chain context</h3>
          </div>
          <span className="pill neutral">{tenants.data?.items.length ?? 0} visible workspaces</span>
        </div>

        <div className="form-grid">
          <label>
            Tenant name
            <input
              value={tenantForm.tenant_name}
              onChange={(event) => setTenantForm((current) => ({ ...current, tenant_name: event.target.value }))}
            />
          </label>
          <label>
            Tenant slug
            <input
              value={tenantForm.tenant_slug}
              onChange={(event) => setTenantForm((current) => ({ ...current, tenant_slug: event.target.value }))}
            />
          </label>
          <label>
            Owner email
            <input
              value={tenantForm.admin_email}
              onChange={(event) => setTenantForm((current) => ({ ...current, admin_email: event.target.value }))}
            />
          </label>
          <label>
            Owner password
            <input
              type="password"
              value={tenantForm.admin_password}
              onChange={(event) => setTenantForm((current) => ({ ...current, admin_password: event.target.value }))}
            />
          </label>
        </div>

        <div className="button-row">
          <button className="primary-button" onClick={() => onboard.mutate()} disabled={onboard.isPending}>
            {onboard.isPending ? "Provisioning..." : "Create Private Tenant"}
          </button>
          {privateTenantId && (
            <>
              <button className="secondary-button" onClick={() => sbomImport.mutate(privateTenantId)} disabled={sbomImport.isPending}>
                {sbomImport.isPending ? "Importing SBOM..." : "Import Sample SBOM"}
              </button>
              <button className="secondary-button" onClick={() => vexImport.mutate(privateTenantId)} disabled={vexImport.isPending}>
                {vexImport.isPending ? "Importing VEX..." : "Import Sample VEX"}
              </button>
            </>
          )}
        </div>

        {onboard.data && (
          <article className="asset-card">
            <strong>{onboard.data.tenant.name}</strong>
            <p className="muted">
              Workspace `{onboard.data.tenant.slug}` created with owner `{onboard.data.user.email}` and {onboard.data.memberships[0]?.role} access.
            </p>
            <p className="muted">Tenant ID {onboard.data.tenant.id}. Access token returned for API clients.</p>
          </article>
        )}

        {(sbomImport.data || vexImport.data) && (
          <div className="action-list">
            {sbomImport.data && (
              <article className="asset-card">
                <strong>SBOM import complete</strong>
                <p className="muted">
                  {sbomImport.data.components_created} components, {sbomImport.data.services_created} services, and {sbomImport.data.dependencies_linked} dependencies materialized.
                </p>
              </article>
            )}
            {vexImport.data && (
              <article className="asset-card">
                <strong>VEX import complete</strong>
                <p className="muted">
                  {vexImport.data.statements_created} statements created and {vexImport.data.statements_updated} updated.
                </p>
              </article>
            )}
          </div>
        )}
      </section>

      <section className="detail-card">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Governance Trail</p>
            <h3>Approvals, feedback, and audit chain</h3>
          </div>
        </div>

        <div className="metric-grid compact">
          <article className="metric-card">
            <div className="metric-value">{approvals.data?.items.length ?? 0}</div>
            <div className="metric-label">Approvals</div>
          </article>
          <article className="metric-card">
            <div className="metric-value">{feedback.data?.items.length ?? 0}</div>
            <div className="metric-label">Feedback items</div>
          </article>
          <article className="metric-card">
            <div className="metric-value">{audit.data?.items.length ?? 0}</div>
            <div className="metric-label">Audit events</div>
          </article>
        </div>

        <div className="stack-grid">
          <div className="panel inset">
            <p className="eyebrow">Recent approvals</p>
            <div className="action-list">
              {approvals.data?.items.slice(0, 3).map((item) => (
                <article key={item.id} className="asset-card">
                  <div className="list-row">
                    <strong>{item.patch_id}</strong>
                    <span className="pill neutral">{item.approval_state}</span>
                  </div>
                  <p className="muted">{item.note}</p>
                </article>
              ))}
            </div>
          </div>

          <div className="panel inset">
            <p className="eyebrow">Recent analyst feedback</p>
            <div className="action-list">
              {feedback.data?.items.slice(0, 3).map((item) => (
                <article key={item.id} className="asset-card">
                  <div className="list-row">
                    <strong>{item.action_id}</strong>
                    <span className="pill neutral">{item.feedback_type}</span>
                  </div>
                  <p className="muted">{item.note}</p>
                </article>
              ))}
            </div>
          </div>

          <div className="panel inset">
            <p className="eyebrow">Audit chain preview</p>
            <div className="action-list">
              {audit.data?.items.slice(0, 4).map((item) => (
                <article key={item.id} className="asset-card">
                  <strong>{item.summary}</strong>
                  <p className="muted">{item.event_type}</p>
                  <p className="hash-line">{item.event_hash.slice(0, 18)}...</p>
                </article>
              ))}
            </div>
          </div>
        </div>
      </section>
    </section>
  );
}
