"""Debugger orchestration for offensive research workbench."""

from __future__ import annotations

from typing import Any


class DebuggerOrchestrator:
    """gdb (Linux) and WinDbg (Windows) session launcher."""

    def attach(self, *, platform: str, pid: int, symbols_path: str | None = None) -> dict[str, Any]:
        platform = (platform or "linux").lower()
        if platform not in {"linux", "windows"}:
            raise ValueError(f"platform_not_supported:{platform}")
        debugger = "gdb" if platform == "linux" else "windbg"
        return {
            "debugger": debugger,
            "pid": pid,
            "symbols_path": symbols_path,
            "status": "attached_simulated",
        }
