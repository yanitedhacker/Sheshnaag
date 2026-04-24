import { useEffect, useRef, useState } from "react";
import type { Citation } from "../types";

export type AISidebarMessage = {
  role: "system" | "user" | "assistant";
  content: string;
  citations?: Citation[];
  timestamp?: string;
};

export type AISidebarProps = {
  title?: string;
  messages: AISidebarMessage[];
  onSubmit?: (prompt: string) => Promise<void> | void;
  busy?: boolean;
  groundingItems?: Array<{ kind: string; title: string; summary?: string | null }>;
  emptyState?: string;
};

/**
 * Reusable side panel that streams an AI session next to whatever surface
 * the analyst is on. Lives outside any single page so we can mount it in
 * AttackCoverage, CaseGraph, RunConsole, etc.
 */
export function AISidebar({
  title = "AI Analyst",
  messages,
  onSubmit,
  busy = false,
  groundingItems,
  emptyState = "Ask a grounded question about the current view.",
}: AISidebarProps) {
  const [draft, setDraft] = useState("");
  const listRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const node = listRef.current;
    if (node) {
      node.scrollTop = node.scrollHeight;
    }
  }, [messages]);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!draft.trim() || !onSubmit) return;
    const prompt = draft.trim();
    setDraft("");
    await onSubmit(prompt);
  };

  return (
    <aside className="ai-sidebar" aria-label="AI analyst sidebar">
      <header className="ai-sidebar-header">
        <h3>{title}</h3>
        {busy ? <span className="status-pill">streaming…</span> : null}
      </header>

      {groundingItems && groundingItems.length > 0 ? (
        <section className="ai-sidebar-grounding">
          <h4>Grounding</h4>
          <ul>
            {groundingItems.slice(0, 10).map((item, idx) => (
              <li key={`${item.kind}-${idx}`}>
                <strong>{item.kind}</strong> — {item.title}
                {item.summary ? <span className="muted"> · {item.summary}</span> : null}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <div className="ai-sidebar-messages" ref={listRef}>
        {messages.length === 0 ? (
          <p className="muted">{emptyState}</p>
        ) : (
          messages.map((message, idx) => (
            <article key={idx} className={`ai-sidebar-message ai-sidebar-message-${message.role}`}>
              <header>
                <span className="status-pill">{message.role}</span>
                {message.timestamp ? <span className="muted">{message.timestamp}</span> : null}
              </header>
              <p>{message.content}</p>
              {message.citations && message.citations.length > 0 ? (
                <ul className="ai-sidebar-citations">
                  {message.citations.map((citation, cidx) => (
                    <li key={cidx}>
                      <span>{citation.label}</span>
                      {citation.url ? (
                        <a href={citation.url} target="_blank" rel="noreferrer">
                          source
                        </a>
                      ) : null}
                      {citation.detail ? <span className="muted"> · {citation.detail}</span> : null}
                    </li>
                  ))}
                </ul>
              ) : null}
            </article>
          ))
        )}
      </div>

      {onSubmit ? (
        <form className="ai-sidebar-form" onSubmit={handleSubmit}>
          <textarea
            placeholder="Ask a grounded question…"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            rows={3}
          />
          <button type="submit" className="primary-button" disabled={!draft.trim() || busy}>
            Send
          </button>
        </form>
      ) : null}
    </aside>
  );
}
