import { useState } from "react";
import type { Citation } from "../types";

export type GroundingInspectorItem = {
  id?: string;
  kind: string;
  title: string;
  summary?: string | null;
  url?: string | null;
  citations?: Citation[];
  payload?: Record<string, unknown>;
};

export type GroundingInspectorProps = {
  items: GroundingInspectorItem[];
  title?: string;
  emptyState?: string;
};

/**
 * Surface that lets reviewers inspect every grounding item the AI used.
 * The key promise of V4 is "no AI claim without reviewable grounding" —
 * this component is how that promise becomes visible to operators.
 */
export function GroundingInspector({
  items,
  title = "Grounding inspector",
  emptyState = "No grounding items captured for this session.",
}: GroundingInspectorProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  if (items.length === 0) {
    return (
      <section className="grounding-inspector">
        <h3>{title}</h3>
        <p className="muted">{emptyState}</p>
      </section>
    );
  }

  return (
    <section className="grounding-inspector">
      <h3>
        {title} <span className="status-pill">{items.length}</span>
      </h3>
      <ul>
        {items.map((item, idx) => {
          const key = item.id ?? `${item.kind}-${idx}`;
          const isExpanded = expanded[key] ?? false;
          return (
            <li key={key} className="grounding-inspector-item">
              <header>
                <span className="status-pill">{item.kind}</span>
                <strong>{item.title}</strong>
                <button
                  type="button"
                  className="ghost-button"
                  onClick={() =>
                    setExpanded((prev) => ({ ...prev, [key]: !isExpanded }))
                  }
                >
                  {isExpanded ? "Hide" : "Inspect"}
                </button>
              </header>
              {item.summary ? <p className="muted">{item.summary}</p> : null}
              {isExpanded ? (
                <div className="grounding-inspector-details">
                  {item.url ? (
                    <p>
                      <a href={item.url} target="_blank" rel="noreferrer">
                        Open source
                      </a>
                    </p>
                  ) : null}
                  {item.citations && item.citations.length > 0 ? (
                    <ul>
                      {item.citations.map((citation, cidx) => (
                        <li key={cidx}>
                          {citation.label}
                          {citation.url ? (
                            <>
                              {" "}
                              ·{" "}
                              <a href={citation.url} target="_blank" rel="noreferrer">
                                link
                              </a>
                            </>
                          ) : null}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                  {item.payload ? (
                    <pre className="grounding-inspector-payload">
                      {JSON.stringify(item.payload, null, 2)}
                    </pre>
                  ) : null}
                </div>
              ) : null}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
