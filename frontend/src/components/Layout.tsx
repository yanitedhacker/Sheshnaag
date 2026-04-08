import { Link, Outlet } from "react-router-dom";

const navItems = [
  { href: "#platform", label: "Platform" },
  { href: "#safety", label: "Safety" },
  { href: "#architecture", label: "Architecture" },
  { href: "#roadmap", label: "Roadmap" },
];

export function Layout() {
  return (
    <div className="marketing-shell">
      <header className="marketing-header">
        <a className="brand-lockup" href="#top">
          <span className="brand-marketing-mark">SN</span>
          <span>
            <strong>Project Sheshnaag</strong>
            <small>Defensive vulnerability research lab</small>
          </span>
        </a>

        <nav className="marketing-nav" aria-label="Primary">
          {navItems.map((item) => (
            <a key={item.href} href={item.href}>
              {item.label}
            </a>
          ))}
          <Link to="/recipes">Recipes</Link>
        </nav>

        <div className="marketing-actions">
          <a className="ghost-button" href="/docs" target="_blank" rel="noreferrer">
            API Docs
          </a>
          <a className="primary-button" href="/api/intel/overview" target="_blank" rel="noreferrer">
            Live Intel
          </a>
        </div>
      </header>

      <Outlet />
    </div>
  );
}
