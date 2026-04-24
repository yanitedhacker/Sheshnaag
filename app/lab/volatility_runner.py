"""Volatility 3 post-execution memory forensics runner.

Wraps the ``vol`` CLI to execute a catalog of memory plugins against a captured
memory image, normalizes the JSON rows into ``BehaviorFinding``-shaped dicts
with ``finding_type`` prefixed ``memory:``, and never raises on missing binary
or subprocess failure (all errors downgrade to an empty result).

Plugins are ``windows.*`` by default; ``linux.*`` equivalents are swapped in
when the caller passes ``os_hint="linux"``. Confidence is derived from the
signal strength of the plugin kind (e.g. a ``hollowfind`` hit is near-certain
process hollowing, whereas ``pslist`` is largely informational).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# -- Plugin catalog -----------------------------------------------------------

DEFAULT_WINDOWS_PLUGINS: List[str] = [
    "windows.pslist",
    "windows.malfind",
    "windows.netscan",
    "windows.cmdline",
    "windows.hollowfind",
    "windows.modscan",
]

DEFAULT_LINUX_PLUGINS: List[str] = [
    "linux.pslist",
    "linux.malfind",
    "linux.netstat",
    "linux.bash",
    "linux.check_modules",
    "linux.lsmod",
]

# Plugins mapped to (severity, baseline_confidence, hit_confidence) triples.
# baseline_confidence is used when the plugin returns rows that are purely
# informational (e.g. pslist). hit_confidence is used for rows that represent
# a suspicious artifact (malfind, hollowfind, rootkit modules).
_PLUGIN_KIND: Dict[str, Dict[str, Any]] = {
    "pslist": {"severity": "info", "baseline": 0.3, "hit": 0.3, "hit_signal": False},
    "malfind": {"severity": "high", "baseline": 0.85, "hit": 0.9, "hit_signal": True},
    "netscan": {"severity": "medium", "baseline": 0.55, "hit": 0.7, "hit_signal": False},
    "netstat": {"severity": "medium", "baseline": 0.55, "hit": 0.7, "hit_signal": False},
    "cmdline": {"severity": "info", "baseline": 0.4, "hit": 0.55, "hit_signal": False},
    "hollowfind": {"severity": "critical", "baseline": 0.95, "hit": 0.95, "hit_signal": True},
    "modscan": {"severity": "medium", "baseline": 0.6, "hit": 0.75, "hit_signal": False},
    "bash": {"severity": "info", "baseline": 0.4, "hit": 0.55, "hit_signal": False},
    "check_modules": {"severity": "high", "baseline": 0.85, "hit": 0.9, "hit_signal": True},
    "lsmod": {"severity": "info", "baseline": 0.3, "hit": 0.3, "hit_signal": False},
}


def _plugin_kind_key(plugin: str) -> str:
    # e.g. "windows.malfind" -> "malfind"
    return plugin.rsplit(".", 1)[-1].lower() if plugin else ""


def _plugin_severity(plugin: str) -> str:
    return _PLUGIN_KIND.get(_plugin_kind_key(plugin), {"severity": "info"})["severity"]


def _env_dry_run_default() -> bool:
    val = os.environ.get("SHESHNAAG_VOLATILITY_DRY_RUN", "").strip().lower()
    return val in {"1", "true", "yes", "on"}


class VolatilityRunner:
    """Thin subprocess wrapper around Volatility 3.

    Callers should treat the runner as best-effort: if ``vol`` is missing or
    any invocation fails, :meth:`run` returns an empty list and logs a warning
    rather than raising.
    """

    def __init__(
        self,
        *,
        vol_binary: Optional[str] = None,
        plugins: Optional[List[str]] = None,
        dry_run: Optional[bool] = None,
    ) -> None:
        self.vol_binary = vol_binary or os.environ.get("SHESHNAAG_VOLATILITY_BIN", "vol")
        self._explicit_plugins = list(plugins) if plugins else None
        self.dry_run = _env_dry_run_default() if dry_run is None else bool(dry_run)

    # -- Health ---------------------------------------------------------------

    def _binary_path(self) -> Optional[str]:
        if os.path.isabs(self.vol_binary) and os.path.exists(self.vol_binary):
            return self.vol_binary
        return shutil.which(self.vol_binary)

    def health(self) -> Dict[str, Any]:
        """Return a lightweight health snapshot.

        Never raises. Returns ``healthy=False`` when the binary cannot be
        located or returns a non-zero exit on ``--help``.
        """
        path = self._binary_path()
        if not path:
            return {
                "tool": "volatility3",
                "binary": self.vol_binary,
                "resolved_path": None,
                "version": None,
                "healthy": False,
                "reason": "binary_not_found",
            }
        try:
            proc = subprocess.run(
                [path, "--help"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            version = _extract_version(proc.stdout or "") or _extract_version(proc.stderr or "")
            healthy = proc.returncode == 0
            return {
                "tool": "volatility3",
                "binary": self.vol_binary,
                "resolved_path": path,
                "version": version,
                "healthy": healthy,
                "reason": None if healthy else f"exit_{proc.returncode}",
            }
        except (subprocess.SubprocessError, OSError) as exc:
            return {
                "tool": "volatility3",
                "binary": self.vol_binary,
                "resolved_path": path,
                "version": None,
                "healthy": False,
                "reason": f"probe_failed: {exc}",
            }

    # -- Execution ------------------------------------------------------------

    def plugins_for(self, os_hint: str) -> List[str]:
        if self._explicit_plugins is not None:
            return list(self._explicit_plugins)
        if (os_hint or "").strip().lower() == "linux":
            return list(DEFAULT_LINUX_PLUGINS)
        return list(DEFAULT_WINDOWS_PLUGINS)

    def run(self, *, memory_dump_path: str, os_hint: str = "windows") -> List[Dict[str, Any]]:
        """Invoke every configured plugin and return normalized findings.

        Parameters
        ----------
        memory_dump_path:
            Host-visible path to the memory capture (``.raw``/``.lime``).
        os_hint:
            Either ``"windows"`` or ``"linux"``. Chooses the default plugin
            catalog when the caller did not override ``plugins``.
        """
        findings: List[Dict[str, Any]] = []
        if not memory_dump_path:
            logger.warning("volatility_runner: empty memory_dump_path")
            return findings

        path = self._binary_path()
        if not path:
            logger.warning("volatility_runner: binary '%s' not found; returning []", self.vol_binary)
            return findings

        if not os.path.isfile(memory_dump_path):
            logger.warning(
                "volatility_runner: memory_dump_path %s does not exist; returning []",
                memory_dump_path,
            )
            return findings

        for plugin in self.plugins_for(os_hint):
            if self.dry_run:
                continue
            rows = self._run_plugin(path, memory_dump_path, plugin)
            for row in rows:
                findings.append(self._normalize(plugin, row))
        return findings

    def _run_plugin(
        self,
        vol_path: str,
        memory_dump_path: str,
        plugin: str,
    ) -> List[Dict[str, Any]]:
        cmd = [vol_path, "-f", memory_dump_path, "--renderer=json", plugin]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            logger.warning("volatility_runner: plugin %s timed out", plugin)
            return []
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("volatility_runner: plugin %s failed to spawn: %s", plugin, exc)
            return []

        if proc.returncode != 0:
            logger.warning(
                "volatility_runner: plugin %s exited %s: %s",
                plugin,
                proc.returncode,
                (proc.stderr or "")[:500],
            )
            return []

        return _parse_vol_json(proc.stdout or "")

    # -- Normalization --------------------------------------------------------

    def _normalize(self, plugin: str, row: Dict[str, Any]) -> Dict[str, Any]:
        kind_key = _plugin_kind_key(plugin)
        kind = _PLUGIN_KIND.get(kind_key, {
            "severity": "info",
            "baseline": 0.3,
            "hit": 0.3,
            "hit_signal": False,
        })
        suspicious = _row_is_suspicious(kind_key, row)
        confidence = float(kind["hit"]) if suspicious else float(kind["baseline"])
        title = _title_for_row(plugin, row) or plugin
        return {
            "plugin": plugin,
            "title": title,
            "severity": kind["severity"],
            "confidence": round(confidence, 3),
            "finding_type": f"memory:{kind_key}",
            "payload": {
                "plugin": plugin,
                "row": row,
                "suspicious": suspicious,
            },
        }


# -- Helpers ------------------------------------------------------------------


def _extract_version(text: str) -> Optional[str]:
    # Volatility prints "Volatility 3 Framework 2.5.2" in help header.
    if not text:
        return None
    for line in text.splitlines():
        lowered = line.lower()
        if "volatility" in lowered and any(ch.isdigit() for ch in line):
            # Pick the last whitespace token that starts with a digit.
            tokens = [t for t in line.split() if t and t[0].isdigit()]
            if tokens:
                return tokens[-1]
    return None


def _parse_vol_json(text: str) -> List[Dict[str, Any]]:
    """Parse the JSON rendered by ``vol --renderer=json``.

    Volatility 3 emits either a JSON array of row-dicts or (occasionally) one
    JSON object per line. Handle both shapes defensively.
    """
    text = (text or "").strip()
    if not text:
        return []

    # Try full-document parse first.
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None

    rows: List[Dict[str, Any]] = []
    if isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, dict):
                rows.append(item)
        return rows
    if isinstance(parsed, dict):
        # Some plugin outputs wrap the rows under a key like "rows"/"data".
        for key in ("rows", "data", "results"):
            val = parsed.get(key)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        rows.append(item)
                return rows
        # Otherwise treat the dict itself as a single row.
        return [parsed]

    # Fall back to JSON-lines.
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    rows.append(item)
    return rows


def _row_is_suspicious(kind_key: str, row: Dict[str, Any]) -> bool:
    """Heuristics that promote a row from baseline to hit-confidence."""
    if not isinstance(row, dict):
        return False
    lowered = {str(k).lower(): v for k, v in row.items()}
    if kind_key == "malfind":
        # Any malfind output is a suspicious injection signal.
        return True
    if kind_key == "hollowfind":
        return True
    if kind_key == "check_modules":
        hidden = lowered.get("hidden") or lowered.get("is_hidden")
        if isinstance(hidden, bool):
            return hidden
        return bool(hidden)
    if kind_key == "netscan" or kind_key == "netstat":
        state = str(lowered.get("state") or "").upper()
        foreign = str(lowered.get("foreignaddr") or lowered.get("foreign_addr") or lowered.get("foreign"))
        return state == "ESTABLISHED" and bool(foreign) and not foreign.startswith(("0.0.0.0", "127.", "::1"))
    if kind_key == "cmdline":
        args = str(lowered.get("args") or lowered.get("cmdline") or "").lower()
        return any(needle in args for needle in ("powershell -enc", "rundll32", "cscript", "mshta"))
    if kind_key == "modscan":
        name = str(lowered.get("name") or lowered.get("module") or "").lower()
        return name.endswith(".sys") and any(token in name for token in ("\\temp\\", "\\users\\"))
    return False


def _title_for_row(plugin: str, row: Dict[str, Any]) -> str:
    lowered = {str(k).lower(): v for k, v in row.items()}
    label = None
    for key in ("processname", "process", "imagefilename", "name", "module", "command"):
        if lowered.get(key):
            label = str(lowered[key])
            break
    pid = lowered.get("pid") or lowered.get("processid")
    if label and pid:
        return f"{plugin}: {label} (pid {pid})"
    if label:
        return f"{plugin}: {label}"
    if pid:
        return f"{plugin}: pid {pid}"
    return plugin
