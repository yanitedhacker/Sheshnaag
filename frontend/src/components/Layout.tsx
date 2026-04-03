import { NavLink, Outlet } from "react-router-dom";

const navItems = [
  { to: "/", label: "Workbench" },
  { to: "/graph", label: "Attack Graph" },
  { to: "/simulator", label: "Simulator" },
  { to: "/assets", label: "Asset Explorer" },
  { to: "/trust", label: "Trust Center" },
  { to: "/operations", label: "Operations" },
];

export function Layout() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">TR</div>
          <div>
            <p className="eyebrow">Exposure-Aware</p>
            <h1>CVE Threat Radar</h1>
          </div>
        </div>

        <nav className="nav">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-panel">
          <p className="eyebrow">Demo Tenant</p>
          <strong>demo-public</strong>
          <p className="muted">Read-only seeded environment with attack paths, KEV/EPSS enrichments, and simulation-ready patches.</p>
        </div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div>
            <p className="eyebrow">Operator Console</p>
            <h2>Exposure-aware remediation workbench</h2>
          </div>
          <a className="ghost-button" href="/docs" target="_blank" rel="noreferrer">
            API Docs
          </a>
        </header>
        <Outlet />
      </main>
    </div>
  );
}
