"""AI-assisted crash triage for offensive research."""

from __future__ import annotations

from typing import Any


class CrashTriage:
    """Classify crashes as exploitable / not exploitable / needs review."""

    def triage(self, *, crash: dict[str, Any]) -> dict[str, Any]:
        signal = (crash.get("signal") or "").upper()
        if signal in {"SIGSEGV", "SIGILL"}:
            verdict = "exploitable"
            confidence = 0.82
        elif signal in {"SIGABRT"}:
            verdict = "needs_review"
            confidence = 0.55
        else:
            verdict = "not_exploitable"
            confidence = 0.71
        return {
            "crash_id": crash.get("crash_id"),
            "verdict": verdict,
            "confidence": confidence,
            "rationale": f"signal={signal} heuristic classification",
        }
