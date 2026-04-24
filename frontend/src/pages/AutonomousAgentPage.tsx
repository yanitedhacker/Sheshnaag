import { useEffect, useState } from "react";
import { api } from "../api";
import { GroundingInspector } from "../components/GroundingInspector";
import type { AutonomousAgentRun, V3AnalysisCaseListResponse } from "../types";

export function AutonomousAgentPage() {
  const [cases, setCases] = useState<V3AnalysisCaseListResponse["items"]>([]);
  const [caseId, setCaseId] = useState<number | undefined>(undefined);
  const [goal, setGoal] = useState("Summarise unresolved findings and ATT&CK posture for the active workspace.");
  const [maxSteps, setMaxSteps] = useState<number>(5);
  const [run, setRun] = useState<AutonomousAgentRun | null>(null);
  const [history, setHistory] = useState<AutonomousAgentRun[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.listAnalysisCases(), api.listAutonomousRuns()])
      .then(([caseResponse, runsResponse]) => {
        if (cancelled) return;
        setCases(caseResponse.items ?? []);
        setHistory(runsResponse.items ?? []);
      })
      .catch((exc: Error) => {
        if (!cancelled) setError(exc.message);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await api.runAutonomousAgent({
        goal,
        case_id: caseId,
        max_steps: maxSteps,
      });
      setRun(response);
      setHistory((prev) => [response, ...prev].slice(0, 20));
    } catch (exc) {
      setError((exc as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="page-section">
      <header className="page-header">
        <h1>Autonomous Analyst Agent</h1>
        <p className="page-subtitle">
          Bounded ReAct loop. Steps inspect findings, ATT&amp;CK posture, and
          existing analyst context — the agent never executes shell commands or
          hits external networks. Every run is gated by the
          <code> autonomous_agent_run </code> capability.
        </p>
      </header>

      <form onSubmit={handleSubmit} className="autonomous-form">
        <label className="checkbox-row">
          <span>Goal</span>
          <textarea
            value={goal}
            onChange={(event) => setGoal(event.target.value)}
            rows={3}
            required
          />
        </label>

        <label className="checkbox-row">
          <span>Case (optional)</span>
          <select
            value={caseId ?? ""}
            onChange={(event) => {
              const next = Number(event.target.value);
              setCaseId(Number.isNaN(next) || next === 0 ? undefined : next);
            }}
          >
            <option value="">— none —</option>
            {cases.map((caseRow) => (
              <option key={caseRow.id} value={caseRow.id}>
                {caseRow.title || `Case ${caseRow.id}`}
              </option>
            ))}
          </select>
        </label>

        <label className="checkbox-row">
          <span>Max steps</span>
          <input
            type="number"
            min={1}
            max={10}
            value={maxSteps}
            onChange={(event) => setMaxSteps(Math.min(10, Math.max(1, Number(event.target.value))))}
          />
        </label>

        <button type="submit" className="primary-button" disabled={busy}>
          {busy ? "Running…" : "Run agent"}
        </button>
      </form>

      {error ? <div className="status-pill status-danger">{error}</div> : null}

      {run ? (
        <article className="autonomous-result">
          <header>
            <h2>Run {run.run_id}</h2>
            <span className={`status-pill${run.status === "denied" ? " status-danger" : ""}`}>
              {run.status}
            </span>
          </header>
          <p>
            <strong>Goal:</strong> {run.goal}
          </p>
          {run.reason ? (
            <p>
              <strong>Reason:</strong> {run.reason}
            </p>
          ) : null}
          <p>
            <strong>Summary:</strong> {run.final_summary || "—"}
          </p>

          <section>
            <h3>Steps</h3>
            <ol>
              {run.steps.map((step) => (
                <li key={step.step}>
                  <strong>{step.tool ?? "thought"}</strong>: {step.thought}
                  {step.tool_output ? (
                    <pre className="autonomous-payload">
                      {JSON.stringify(step.tool_output, null, 2)}
                    </pre>
                  ) : null}
                </li>
              ))}
            </ol>
          </section>

          <GroundingInspector
            items={run.steps.flatMap((step) =>
              (step.citations ?? []).map((citation) => ({
                kind: step.tool ?? "step",
                title: citation.label,
                summary: step.thought,
              })),
            )}
          />
        </article>
      ) : null}

      <section className="autonomous-history">
        <h3>Recent runs ({history.length})</h3>
        <ul>
          {history.map((entry) => (
            <li key={entry.run_id}>
              <span className="status-pill">{entry.status}</span> {entry.goal}
            </li>
          ))}
        </ul>
      </section>
    </section>
  );
}
