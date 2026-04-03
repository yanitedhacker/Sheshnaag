import type { WorkbenchAction } from "../types";

export function SignalPills({ action }: { action: WorkbenchAction }) {
  return (
    <div className="pill-row">
      {action.signals.kev && <span className="pill critical">KEV</span>}
      {action.signals.public_exposure && <span className="pill high">Public Exposure</span>}
      {action.signals.crown_jewel && <span className="pill amber">Crown Jewel</span>}
      {action.signals.exploit_available && <span className="pill high">Exploit Seen</span>}
      {action.signals.epss > 0.7 && <span className="pill neutral">EPSS {action.signals.epss.toFixed(2)}</span>}
      {action.signals.vex_status !== "unknown" && <span className="pill neutral">VEX {action.signals.vex_status}</span>}
      <span className="pill neutral">Approval {action.approval_state}</span>
      {action.feedback_summary && <span className="pill neutral">Feedback {action.feedback_summary.feedback_type}</span>}
    </div>
  );
}
