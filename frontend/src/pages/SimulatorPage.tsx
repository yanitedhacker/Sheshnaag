import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api";

export function SimulatorPage() {
  const baseWorkbench = useQuery({ queryKey: ["workbench"], queryFn: api.getWorkbench });
  const [form, setForm] = useState({
    delay_days: 14,
    downtime_budget_minutes: 60,
    team_capacity: 2,
    public_exposure_weight: 1.25,
    crown_jewel_weight: 1.15,
    compensating_controls: false,
  });

  const simulation = useMutation({
    mutationFn: () =>
      api.runSimulation({
        ...form,
        tenant_slug: "demo-public",
      }),
  });

  const topBefore = useMemo(() => baseWorkbench.data?.actions.slice(0, 5) ?? [], [baseWorkbench.data]);

  return (
    <section className="simulator-grid">
      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">What-If Workbench</p>
            <h3>Stress your patch plan</h3>
          </div>
        </div>

        <div className="form-grid">
          <label>
            Delay days
            <input
              type="number"
              value={form.delay_days}
              onChange={(event) => setForm((current) => ({ ...current, delay_days: Number(event.target.value) }))}
            />
          </label>
          <label>
            Downtime budget (minutes)
            <input
              type="number"
              value={form.downtime_budget_minutes}
              onChange={(event) =>
                setForm((current) => ({ ...current, downtime_budget_minutes: Number(event.target.value) }))
              }
            />
          </label>
          <label>
            Team capacity
            <input
              type="number"
              value={form.team_capacity}
              onChange={(event) => setForm((current) => ({ ...current, team_capacity: Number(event.target.value) }))}
            />
          </label>
          <label>
            Public exposure weight
            <input
              type="number"
              step="0.05"
              value={form.public_exposure_weight}
              onChange={(event) =>
                setForm((current) => ({ ...current, public_exposure_weight: Number(event.target.value) }))
              }
            />
          </label>
          <label>
            Crown jewel weight
            <input
              type="number"
              step="0.05"
              value={form.crown_jewel_weight}
              onChange={(event) =>
                setForm((current) => ({ ...current, crown_jewel_weight: Number(event.target.value) }))
              }
            />
          </label>
          <label>
            Compensating controls
            <select
              value={String(form.compensating_controls)}
              onChange={(event) =>
                setForm((current) => ({ ...current, compensating_controls: event.target.value === "true" }))
              }
            >
              <option value="false">Disabled</option>
              <option value="true">Enabled</option>
            </select>
          </label>
        </div>

        <button className="primary-button" onClick={() => simulation.mutate()} disabled={simulation.isPending}>
          {simulation.isPending ? "Running..." : "Run Simulation"}
        </button>
      </section>

      <section className="detail-card">
        {!simulation.data ? (
          <>
            <p className="eyebrow">Current Baseline</p>
            <div className="action-list">
              {topBefore.map((action) => (
                <article key={action.action_id} className="action-card">
                  <div className="list-row">
                    <strong>{action.title}</strong>
                    <div className="score">{action.actionable_risk_score.toFixed(0)}</div>
                  </div>
                  <p className="muted">{action.recommended_action}</p>
                </article>
              ))}
            </div>
          </>
        ) : (
          <>
            <div className="panel-header">
              <div>
                <p className="eyebrow">Simulation Result</p>
                <h3>Expected risk reduction {simulation.data.summary.expected_risk_reduction.toFixed(2)}</h3>
              </div>
              <span className="pill neutral">{simulation.data.summary.actions_selected} patches selected</span>
            </div>

            <div className="action-list">
              {simulation.data.after.actions.slice(0, 6).map((action) => (
                <article key={action.action_id} className="action-card">
                  <div className="list-row">
                    <strong>{action.title}</strong>
                    <span className={`pill ${action.selected_for_window ? "critical" : "neutral"}`}>
                      {action.selected_for_window ? "selected" : "deferred"}
                    </span>
                  </div>
                  <div className="inline-meta">
                    <span>Before {action.actionable_risk_score.toFixed(1)}</span>
                    <span>After {action.post_simulation_risk_score.toFixed(1)}</span>
                  </div>
                </article>
              ))}
            </div>

            <div className="path-list">
              {simulation.data.schedule.schedule.map((window) => (
                <article key={window.window} className="path-card">
                  <strong>{window.window}</strong>
                  <p className="muted">{window.patches.join(", ") || "No patches scheduled"}</p>
                  <div className="inline-meta">
                    <span>{window.total_downtime}m downtime</span>
                    <span>{Math.round(window.risk_reduction * 100)}% reduction</span>
                  </div>
                </article>
              ))}
            </div>
          </>
        )}
      </section>
    </section>
  );
}
