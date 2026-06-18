import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api, getActiveTenantSlug, storeWorkspaceSlug } from "../api";
import type { TenantWorkspace } from "../types";
import { ROUTE_PERMISSIONS, type PermissionSlug } from "../permissions";
import { useCurrentRole } from "../hooks/useCurrentRole";

type NavItem = {
  to: string;
  label: string;
  /** Path key into ROUTE_PERMISSIONS (no leading slash). */
  permissionKey: keyof typeof ROUTE_PERMISSIONS;
};

const operatorNavItems: NavItem[] = [
  { to: "/intel", label: "Intel", permissionKey: "intel" },
  { to: "/review", label: "Review", permissionKey: "review" },
  { to: "/candidates", label: "Candidates", permissionKey: "candidates" },
  { to: "/recipes", label: "Recipes", permissionKey: "recipes" },
  { to: "/runs", label: "Runs", permissionKey: "runs" },
  { to: "/authorization", label: "Auth", permissionKey: "authorization" },
  { to: "/attack-coverage", label: "ATT&CK", permissionKey: "attack-coverage" },
  { to: "/case-graph", label: "Graph", permissionKey: "case-graph" },
  { to: "/autonomous", label: "Agent", permissionKey: "autonomous" },
  { to: "/evidence", label: "Evidence", permissionKey: "evidence" },
  { to: "/artifacts", label: "Artifacts", permissionKey: "artifacts" },
  { to: "/provenance", label: "Provenance", permissionKey: "provenance" },
  { to: "/ledger", label: "Ledger", permissionKey: "ledger" },
  { to: "/disclosures", label: "Bundles", permissionKey: "disclosures" },
  { to: "/specimens", label: "Specimens", permissionKey: "specimens" },
  { to: "/analysis-cases", label: "Cases", permissionKey: "analysis-cases" },
  { to: "/sandbox-profiles", label: "Profiles", permissionKey: "sandbox-profiles" },
  { to: "/findings", label: "Findings", permissionKey: "findings" },
  { to: "/indicators", label: "Indicators", permissionKey: "indicators" },
  { to: "/prevention-v3", label: "Prevention", permissionKey: "prevention-v3" },
  { to: "/defang", label: "Defang", permissionKey: "defang" },
  { to: "/reports", label: "Reports", permissionKey: "reports" },
  { to: "/ai-sessions", label: "AI Drafts", permissionKey: "ai-sessions" },
  { to: "/policy", label: "Policy", permissionKey: "policy" },
  { to: "/workers", label: "Workers", permissionKey: "workers" },
  { to: "/analytics", label: "Analytics", permissionKey: "analytics" },
  { to: "/purple-team", label: "Purple", permissionKey: "purple-team" },
  { to: "/research", label: "Research", permissionKey: "research" },
];

export function Layout() {
  const [workspaces, setWorkspaces] = useState<TenantWorkspace[]>([]);
  const [activeSlug, setActiveSlug] = useState<string>("");

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.getTenants(), getActiveTenantSlug()])
      .then(([tenants, slug]) => {
        if (cancelled) {
          return;
        }
        setWorkspaces(tenants.items);
        setActiveSlug(slug);
      })
      .catch(() => null);
    return () => {
      cancelled = true;
    };
  }, []);

  const activeWorkspace = workspaces.find((item) => item.tenant_slug === activeSlug) ?? null;

  return (
    <div className="app-shell">
      <header className="app-header">
        <NavLink className="brand-lockup" to="/intel">
          <span className="brand-marketing-mark">SN</span>
          <span>
            <strong>Project Sheshnaag</strong>
            <small>Operator console for defensive validation</small>
          </span>
        </NavLink>

        <nav className="operator-nav" aria-label="Operator">
          {operatorNavItems.map((item) => {
            const requiredPermission: PermissionSlug =
              ROUTE_PERMISSIONS[item.permissionKey];
            return (
              <RoleAwareNavLink
                key={item.to}
                to={item.to}
                label={item.label}
                permission={requiredPermission}
              />
            );
          })}
        </nav>

        <div className="marketing-actions">
          <label className="checkbox-row" style={{ gap: "0.5rem" }}>
            <span>Workspace</span>
            <select
              value={activeSlug}
              onChange={(event) => {
                const nextSlug = event.target.value;
                storeWorkspaceSlug(nextSlug);
                setActiveSlug(nextSlug);
                window.location.reload();
              }}
            >
              {workspaces.map((workspace) => (
                <option key={workspace.tenant_slug} value={workspace.tenant_slug}>
                  {workspace.tenant_name}
                  {workspace.is_demo ? " (demo)" : ""}
                  {workspace.is_read_only ? " [read-only]" : ""}
                </option>
              ))}
            </select>
          </label>
          {activeWorkspace ? (
            <span className={`status-pill${activeWorkspace.is_read_only ? " status-danger" : ""}`}>
              {activeWorkspace.tenant_slug}
            </span>
          ) : null}
          <a className="ghost-button" href="/docs" target="_blank" rel="noreferrer">
            API Docs
          </a>
          <a className="primary-button" href={activeSlug ? `/api/intel/overview?tenant_slug=${activeSlug}` : "/api/intel/overview"} target="_blank" rel="noreferrer">
            Live Intel
          </a>
        </div>
      </header>

      <main className="app-content">
        <Outlet />
      </main>
    </div>
  );
}


function RoleAwareNavLink({
  to,
  label,
  permission,
}: {
  to: string;
  label: string;
  permission: PermissionSlug;
}) {
  const { hasPermission, isAuthenticated } = useCurrentRole();
  // V5 dev: when no token is present (auth_enabled=False on the
  // backend, anonymous fallthrough), keep the nav fully visible so
  // local development is not blocked. Real deployments will always
  // have a token.
  if (isAuthenticated && !hasPermission(permission)) {
    return null;
  }
  return (
    <NavLink
      to={to}
      className={({ isActive }) => `operator-link${isActive ? " is-active" : ""}`}
    >
      {label}
    </NavLink>
  );
}
