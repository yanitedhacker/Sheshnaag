import { Link } from "react-router-dom";
import { useCurrentRole } from "../hooks/useCurrentRole";

export function NotAuthorizedPage() {
  const { roles, isAuthenticated } = useCurrentRole();

  return (
    <section className="page-shell">
      <header className="page-header">
        <h1>Not authorized</h1>
        <p>
          {isAuthenticated
            ? "Your role does not include the permission required for this page."
            : "You are not signed in."}
        </p>
      </header>

      {isAuthenticated && roles.length > 0 ? (
        <p>
          Current roles: <code>{roles.join(", ")}</code>. Contact a lab lead if
          you believe this is wrong.
        </p>
      ) : null}

      <p>
        <Link to="/intel">Return to Intel dashboard</Link>
      </p>
    </section>
  );
}
