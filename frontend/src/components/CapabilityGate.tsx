import { cloneElement, ReactElement, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { CapabilityCheckResponse } from "../types";

type GateChild = ReactElement<{ disabled?: boolean; title?: string; className?: string }>;

export function CapabilityGate({
  capability,
  scope = {},
  children,
}: {
  capability: string;
  scope?: Record<string, unknown>;
  children: GateChild;
}) {
  const [decision, setDecision] = useState<CapabilityCheckResponse | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.checkCapability(capability, scope)
      .then((result) => {
        if (!cancelled) {
          setDecision(result);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setDecision({ permitted: false, reason: "check_failed", artifact_id: null });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [capability, JSON.stringify(scope)]);

  if (decision?.permitted) {
    return children;
  }

  return (
    <span className="capability-gate">
      {cloneElement(children, {
        disabled: true,
        title: `Needs ${capability} authorization`,
        className: `${children.props.className ?? ""} is-disabled`.trim(),
      })}
      <Link className="ghost-button" to={`/authorization?capability=${encodeURIComponent(capability)}`}>
        Request
      </Link>
    </span>
  );
}
