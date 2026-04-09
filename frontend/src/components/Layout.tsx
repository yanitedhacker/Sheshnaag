import { NavLink, Outlet } from "react-router-dom";

const operatorNavItems = [
  { to: "/intel", label: "Intel" },
  { to: "/candidates", label: "Candidates" },
  { to: "/recipes", label: "Recipes" },
  { to: "/runs", label: "Runs" },
  { to: "/evidence", label: "Evidence" },
  { to: "/artifacts", label: "Artifacts" },
  { to: "/provenance", label: "Provenance" },
  { to: "/ledger", label: "Ledger" },
  { to: "/disclosures", label: "Bundles" },
];

export function Layout() {
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
          <NavLink className="ghost-button" to="/story">
            Story
          </NavLink>
          <a className="ghost-button" href="/docs" target="_blank" rel="noreferrer">
            API Docs
          </a>
          <a className="primary-button" href="/api/intel/overview" target="_blank" rel="noreferrer">
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
