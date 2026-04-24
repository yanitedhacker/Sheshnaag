import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api, getActiveTenantSlug, storeWorkspaceSlug } from "../api";
import type { TenantWorkspace } from "../types";

const operatorNavItems = [
  { to: "/intel", label: "Intel" },
  { to: "/review", label: "Review" },
  { to: "/candidates", label: "Candidates" },
  { to: "/recipes", label: "Recipes" },
  { to: "/runs", label: "Runs" },
  { to: "/authorization", label: "Auth" },
  { to: "/attack-coverage", label: "ATT&CK" },
  { to: "/case-graph", label: "Graph" },
  { to: "/autonomous", label: "Agent" },
  { to: "/evidence", label: "Evidence" },
  { to: "/artifacts", label: "Artifacts" },
  { to: "/provenance", label: "Provenance" },
  { to: "/ledger", label: "Ledger" },
  { to: "/disclosures", label: "Bundles" },
  { to: "/specimens", label: "Specimens" },
  { to: "/analysis-cases", label: "Cases" },
  { to: "/sandbox-profiles", label: "Profiles" },
  { to: "/findings", label: "Findings" },
  { to: "/indicators", label: "Indicators" },
  { to: "/prevention-v3", label: "Prevention" },
  { to: "/defang", label: "Defang" },
  { to: "/reports", label: "Reports" },
  { to: "/ai-sessions", label: "AI Drafts" },
  { to: "/policy", label: "Policy" },
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
          {operatorNavItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `operator-link${isActive ? " is-active" : ""}`}
            >
              {item.label}
            </NavLink>
          ))}
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
