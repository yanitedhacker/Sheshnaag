import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api } from "../api";

export function CopilotPanel() {
  const [query, setQuery] = useState("Why is the top action ranked first?");
  const presets = [
    "Why is the top action ranked first?",
    "Show attack paths for edge-gateway-01",
    "Generate a CAB-ready patch memo",
    "Summarize this week's top risks",
  ];
  const mutation = useMutation({
    mutationFn: () => api.queryCopilot(query),
  });

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <p className="eyebrow">Grounded Copilot</p>
          <h3>Ask the evidence</h3>
        </div>
      </div>

      <div className="copilot-input">
        <textarea value={query} onChange={(event) => setQuery(event.target.value)} rows={4} />
        <div className="pill-row">
          {presets.map((preset) => (
            <button key={preset} className="ghost-button" onClick={() => setQuery(preset)} type="button">
              {preset}
            </button>
          ))}
        </div>
        <button className="primary-button" onClick={() => mutation.mutate()} disabled={mutation.isPending}>
          {mutation.isPending ? "Analyzing..." : "Run Query"}
        </button>
      </div>

      {mutation.data && (
        <div className="copilot-output">
          {mutation.data.cannot_answer_reason ? (
            <p className="muted">{mutation.data.cannot_answer_reason}</p>
          ) : (
            <>
              <article className="markdown-output">
                {mutation.data.answer_markdown.split("\n").map((line, index) => (
                  <p key={`${line}-${index}`}>{line}</p>
                ))}
              </article>
              {mutation.data.citations.length > 0 && (
                <div className="citation-list">
                  {mutation.data.citations.map((citation) => (
                    <a key={citation.url} href={citation.url} target="_blank" rel="noreferrer">
                      {citation.label}
                    </a>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </section>
  );
}
