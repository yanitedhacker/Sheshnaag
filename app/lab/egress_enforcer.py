"""Kernel-level egress enforcement for Sheshnaag V4 sandbox runs.

This module compiles a ``SandboxProfile``'s declared egress posture
(``egress_mode`` + ``profile.config``) into concrete control-plane artefacts:

* **nftables** rules (L3/L4 allow-list enforced by the kernel).
* **dnsmasq** config for the ``sinkhole`` mode (DNS black-hole answers).
* **INetSim** config for the ``fake_internet`` mode (services replayed from
  a canned corpus so malware "sees" an internet).

The enforcer is deliberately *dry-run by default*.  Applying real kernel rules
requires ``SHESHNAAG_EGRESS_ENFORCE=1`` in the environment **and** the relevant
binaries being present on the host.  When those pre-conditions are not met
the enforcer records its *intent* (so the plan surfaces in reports + logs)
but never executes anything — which keeps CI / mac development environments
happy.

The class is safe to use as a context manager; ``teardown`` is always called
on exit and is idempotent, so leftover rules from a crashed previous run are
reclaimed the next time the same ``run_id`` is apply'd.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import textwrap
from types import TracebackType
from typing import Any, Dict, Iterable, List, Optional, Type

from app.core.time import utc_now

logger = logging.getLogger(__name__)

__all__ = ["EgressEnforcer", "SUPPORTED_MODES"]

SUPPORTED_MODES: tuple[str, ...] = ("none", "default_deny", "sinkhole", "fake_internet")

# Table + chain names are scoped per run so concurrent runs don't collide.
_NFT_TABLE_PREFIX = "sheshnaag_egress"
_DNSMASQ_DIR = os.environ.get("SHESHNAAG_DNSMASQ_RUN_DIR", "/tmp/sheshnaag-dnsmasq")
_INETSIM_DIR = os.environ.get("SHESHNAAG_INETSIM_RUN_DIR", "/tmp/sheshnaag-inetsim")


def _bool_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _slug_run_id(run_id: Any) -> str:
    raw = str(run_id)
    safe = "".join(ch if ch.isalnum() else "_" for ch in raw)
    return safe or "run"


class EgressEnforcer:
    """Compile + apply kernel-level egress rules for one sandbox run.

    Parameters
    ----------
    profile:
        The :class:`SandboxProfile` row backing this run.  We only read
        ``profile.egress_mode``, ``profile.config`` and ``profile.name``; the
        model object is never mutated.
    run_id:
        The ``LabRun.id`` (or equivalent string) — used to scope nft table
        names, dnsmasq pidfiles, and inetsim working dirs so this run's
        rules never stomp on a neighbour.
    dry_run:
        ``True`` (the default if ``SHESHNAAG_EGRESS_ENFORCE`` is unset or
        falsy) means no binary is invoked.  The enforcer still records what
        it would have done.
    """

    def __init__(
        self,
        profile: Any,
        *,
        run_id: Any,
        dry_run: Optional[bool] = None,
    ) -> None:
        self._profile = profile
        self._run_id = run_id
        self._run_slug = _slug_run_id(run_id)

        if dry_run is None:
            dry_run = not _bool_env("SHESHNAAG_EGRESS_ENFORCE")
        self._dry_run = bool(dry_run)

        self._mode = self._resolve_mode(profile)
        self._config: Dict[str, Any] = dict(getattr(profile, "config", None) or {})
        self._allow_hosts = self._resolve_allow_hosts(self._config)
        self._allow_cidrs = self._resolve_allow_cidrs(self._config)
        self._allow_ports = self._resolve_allow_ports(self._config)

        self._nft_table = f"{_NFT_TABLE_PREFIX}_{self._run_slug}"
        self._dnsmasq_pid_path = os.path.join(_DNSMASQ_DIR, f"{self._run_slug}.pid")
        self._dnsmasq_conf_path = os.path.join(_DNSMASQ_DIR, f"{self._run_slug}.conf")
        self._inetsim_dir = os.path.join(_INETSIM_DIR, self._run_slug)
        self._inetsim_conf_path = os.path.join(self._inetsim_dir, "inetsim.conf")
        self._inetsim_pid_path = os.path.join(self._inetsim_dir, "inetsim.pid")

        self._applied: bool = False
        self._last_plan: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def dry_run(self) -> bool:
        return self._dry_run

    @property
    def plan(self) -> Dict[str, Any]:
        return dict(self._last_plan)

    def apply(self) -> Dict[str, Any]:
        """Compile rules and (when not dry-run) push them to the kernel."""
        rules: List[str] = []
        errors: List[str] = []
        binaries: Dict[str, bool] = {
            "nft": self._binary_ok("nft"),
            "dnsmasq": self._binary_ok("dnsmasq"),
            "inetsim": self._binary_ok("inetsim"),
        }

        nft_program = self._nftables_program(self._mode, self._allow_hosts)
        rules.append(nft_program)

        if self._mode == "sinkhole":
            rules.append(self._dnsmasq_config(self._mode, self._run_slug))
        elif self._mode == "fake_internet":
            rules.append(self._inetsim_config(self._mode, self._run_slug))

        applied = False
        if self._dry_run:
            logger.info(
                "egress_enforcer.dry_run",
                extra={
                    "run_id": str(self._run_id),
                    "mode": self._mode,
                    "allow_hosts": self._allow_hosts,
                    "binaries": binaries,
                },
            )
        else:
            applied, apply_errors = self._execute_plan(binaries=binaries, nft_program=nft_program)
            errors.extend(apply_errors)

        plan = {
            "applied": applied,
            "mode": self._mode,
            "rules": rules,
            "errors": errors,
            "dry_run": self._dry_run,
            "binaries": binaries,
            "allow_hosts": list(self._allow_hosts),
            "allow_cidrs": list(self._allow_cidrs),
            "allow_ports": list(self._allow_ports),
            "run_id": str(self._run_id),
            "generated_at": utc_now().isoformat(),
            "nft_table": self._nft_table,
        }
        self._last_plan = plan
        self._applied = applied
        return plan

    def teardown(self) -> None:
        """Idempotently remove all artefacts this enforcer created."""
        if self._dry_run:
            logger.debug(
                "egress_enforcer.teardown.dry_run",
                extra={"run_id": str(self._run_id), "nft_table": self._nft_table},
            )
            self._applied = False
            return

        # nftables: best-effort delete; ignore "No such file or directory" style misses.
        if self._binary_ok("nft"):
            try:
                subprocess.run(
                    ["nft", "delete", "table", "inet", self._nft_table],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
            except (subprocess.SubprocessError, OSError) as exc:
                logger.warning(
                    "egress_enforcer.teardown.nft_failed",
                    extra={"run_id": str(self._run_id), "error": str(exc)},
                )

        # dnsmasq: kill pid recorded at apply time, clean up config.
        self._kill_pidfile(self._dnsmasq_pid_path, label="dnsmasq")
        self._silent_unlink(self._dnsmasq_conf_path)

        # inetsim: kill pid, leave run-dir intact for forensics unless empty.
        self._kill_pidfile(self._inetsim_pid_path, label="inetsim")
        self._silent_unlink(self._inetsim_conf_path)
        try:
            if os.path.isdir(self._inetsim_dir) and not os.listdir(self._inetsim_dir):
                os.rmdir(self._inetsim_dir)
        except OSError:
            pass

        self._applied = False

    # Context-manager surface -------------------------------------------------

    def __enter__(self) -> "EgressEnforcer":
        self.apply()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.teardown()

    # ------------------------------------------------------------------
    # Rule compilation (pure functions; tests exercise these directly)
    # ------------------------------------------------------------------

    def _nftables_program(self, mode: str, allow_hosts: Iterable[str]) -> str:
        """Return an ``nft -f``-ready program describing the egress posture."""
        allow_hosts = list(allow_hosts or [])
        table = self._nft_table
        lines: List[str] = [
            "#!/usr/sbin/nft -f",
            f"# sheshnaag egress enforcer run={self._run_id} mode={mode}",
            f"add table inet {table}",
            f"flush table inet {table}",
            (
                f"add chain inet {table} output "
                "{ type filter hook output priority 0; policy accept; }"
            ),
        ]

        if mode == "none":
            # Pure accept; rules omitted but table is still created so teardown works.
            lines.append(f"# mode=none — no kernel enforcement beyond chain presence")
            return "\n".join(lines) + "\n"

        # Every non-none mode starts from a deny-default posture.
        lines[-1] = (
            f"add chain inet {table} output "
            "{ type filter hook output priority 0; policy drop; }"
        )
        # Always permit loopback.
        lines.append(f"add rule inet {table} output oifname \"lo\" accept")
        # Always permit DNS (we redirect / sinkhole it elsewhere).
        lines.append(f"add rule inet {table} output udp dport 53 accept")
        lines.append(f"add rule inet {table} output tcp dport 53 accept")

        # Allowed CIDRs / ports from profile.config.
        for cidr in self._allow_cidrs:
            family = "ip6" if ":" in cidr else "ip"
            lines.append(f"add rule inet {table} output {family} daddr {cidr} accept")

        for port in self._allow_ports:
            lines.append(f"add rule inet {table} output tcp dport {port} accept")

        # Host allow-list: nft resolves names at load time; store the operator intent.
        for host in allow_hosts:
            host_stripped = str(host).strip()
            if not host_stripped:
                continue
            lines.append(
                f"# allow-host: {host_stripped} (resolved to A/AAAA at rule load)"
            )
            lines.append(
                f"add rule inet {table} output meta l4proto {{tcp,udp}} "
                f"ip daddr $({host_stripped}) accept"
            )

        if mode == "sinkhole":
            # Redirect any non-dns traffic to localhost sinkhole at :9 (discard).
            lines.append(
                f"add rule inet {table} output ip daddr != 127.0.0.0/8 "
                "tcp dport != 53 drop"
            )
            lines.append(
                f"add rule inet {table} output ip daddr != 127.0.0.0/8 "
                "udp dport != 53 drop"
            )
        elif mode == "fake_internet":
            # Accept traffic to the inetsim loopback listener cluster.
            lines.append(
                f"add rule inet {table} output ip daddr 127.0.0.0/8 accept"
            )
            lines.append(
                f"add rule inet {table} output ip daddr 169.254.0.0/16 accept"
            )
            lines.append(
                f"# fake_internet mode: all egress is NAT-redirected into the "
                "inetsim listener; see inetsim.conf"
            )
        else:  # default_deny
            lines.append(f"# default_deny: only explicit allow-rules above will pass")

        lines.append(f"add rule inet {table} output counter log prefix \"sheshnaag-drop: \" drop")
        return "\n".join(lines) + "\n"

    def _dnsmasq_config(self, mode: str, run_id: Any) -> str:
        """Return a dnsmasq config that sinkholes every query to 0.0.0.0."""
        pid_path = self._dnsmasq_pid_path
        slug = _slug_run_id(run_id)
        allow_hosts = self._allow_hosts
        allow_lines = "\n".join(
            f"address=/{host}/127.0.0.1" for host in allow_hosts
        )
        config = textwrap.dedent(
            f"""\
            # sheshnaag dnsmasq sinkhole — run={slug} mode={mode}
            no-resolv
            no-hosts
            bind-interfaces
            listen-address=127.0.0.1
            port=53
            cache-size=0
            log-queries
            log-facility=-
            pid-file={pid_path}
            # Every unknown host → 0.0.0.0 (blackhole).
            address=/#/0.0.0.0
            """
        )
        if allow_lines:
            config += "# operator allow-list overrides\n" + allow_lines + "\n"
        return config

    def _inetsim_config(self, mode: str, run_id: Any) -> str:
        """Return an INetSim config that fakes the top-N internet services."""
        slug = _slug_run_id(run_id)
        data_dir = os.path.join(self._inetsim_dir, "data")
        log_dir = os.path.join(self._inetsim_dir, "log")
        report_dir = os.path.join(self._inetsim_dir, "report")
        return textwrap.dedent(
            f"""\
            # sheshnaag inetsim fake-internet — run={slug} mode={mode}
            start_service dns
            start_service http
            start_service https
            start_service smtp
            start_service pop3
            start_service ftp
            start_service irc
            start_service ntp
            service_bind_address 127.0.0.1
            dns_default_ip 127.0.0.1
            dns_default_hostname sheshnaag-fake
            dns_default_domainname example.invalid
            data_dir {data_dir}
            log_dir {log_dir}
            report_dir {report_dir}
            create_reports yes
            report_language en
            http_fakemode yes
            https_fakemode yes
            http_version sheshnaag-fake/1.0
            """
        )

    # ------------------------------------------------------------------
    # Execution helpers (only touched when dry_run=False)
    # ------------------------------------------------------------------

    def _execute_plan(
        self,
        *,
        binaries: Dict[str, bool],
        nft_program: str,
    ) -> tuple[bool, List[str]]:
        errors: List[str] = []

        if not binaries.get("nft"):
            errors.append("nft binary not found on host; egress rules not applied")
            return False, errors

        try:
            proc = subprocess.run(
                ["nft", "-f", "-"],
                input=nft_program,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if proc.returncode != 0:
                errors.append(
                    f"nft returned {proc.returncode}: {(proc.stderr or '').strip()[:400]}"
                )
                return False, errors
        except (subprocess.SubprocessError, OSError) as exc:
            errors.append(f"nft invocation failed: {exc}")
            return False, errors

        if self._mode == "sinkhole":
            err = self._launch_dnsmasq(binaries=binaries)
            if err:
                errors.append(err)
        elif self._mode == "fake_internet":
            err = self._launch_inetsim(binaries=binaries)
            if err:
                errors.append(err)

        return True, errors

    def _launch_dnsmasq(self, *, binaries: Dict[str, bool]) -> Optional[str]:
        if not binaries.get("dnsmasq"):
            return "dnsmasq binary not found; sinkhole DNS not active"
        try:
            os.makedirs(_DNSMASQ_DIR, exist_ok=True)
            with open(self._dnsmasq_conf_path, "w", encoding="utf-8") as handle:
                handle.write(self._dnsmasq_config(self._mode, self._run_slug))
            proc = subprocess.run(
                [
                    "dnsmasq",
                    "--conf-file=" + self._dnsmasq_conf_path,
                    "--pid-file=" + self._dnsmasq_pid_path,
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if proc.returncode != 0:
                return f"dnsmasq returned {proc.returncode}: {(proc.stderr or '').strip()[:400]}"
        except (subprocess.SubprocessError, OSError) as exc:
            return f"dnsmasq invocation failed: {exc}"
        return None

    def _launch_inetsim(self, *, binaries: Dict[str, bool]) -> Optional[str]:
        if not binaries.get("inetsim"):
            return "inetsim binary not found; fake-internet services not active"
        try:
            os.makedirs(self._inetsim_dir, exist_ok=True)
            with open(self._inetsim_conf_path, "w", encoding="utf-8") as handle:
                handle.write(self._inetsim_config(self._mode, self._run_slug))
            proc = subprocess.Popen(
                [
                    "inetsim",
                    "--conf",
                    self._inetsim_conf_path,
                    "--data-dir",
                    os.path.join(self._inetsim_dir, "data"),
                    "--log-dir",
                    os.path.join(self._inetsim_dir, "log"),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Record pid so teardown can reclaim it without reopening the process.
            with open(self._inetsim_pid_path, "w", encoding="utf-8") as pid_handle:
                pid_handle.write(str(proc.pid))
        except (subprocess.SubprocessError, OSError) as exc:
            return f"inetsim invocation failed: {exc}"
        return None

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _binary_ok(name: str) -> bool:
        return shutil.which(name) is not None

    @staticmethod
    def _resolve_mode(profile: Any) -> str:
        mode = (getattr(profile, "egress_mode", None) or "default_deny").strip().lower()
        if mode not in SUPPORTED_MODES:
            logger.warning(
                "egress_enforcer.unknown_mode",
                extra={"mode": mode, "falling_back_to": "default_deny"},
            )
            mode = "default_deny"
        return mode

    @staticmethod
    def _resolve_allow_hosts(config: Dict[str, Any]) -> List[str]:
        raw: Iterable[Any] = (
            config.get("allow_egress_hosts")
            or config.get("allow_hosts")
            or ((config.get("network_policy") or {}).get("allow_egress_hosts") or [])
            or []
        )
        return [str(item).strip() for item in raw if str(item).strip()]

    @staticmethod
    def _resolve_allow_cidrs(config: Dict[str, Any]) -> List[str]:
        raw: Iterable[Any] = (
            config.get("allow_cidrs")
            or ((config.get("network_policy") or {}).get("allow_cidrs") or [])
            or []
        )
        return [str(item).strip() for item in raw if str(item).strip()]

    @staticmethod
    def _resolve_allow_ports(config: Dict[str, Any]) -> List[int]:
        raw: Iterable[Any] = (
            config.get("allow_ports")
            or ((config.get("network_policy") or {}).get("allow_ports") or [])
            or []
        )
        ports: List[int] = []
        for item in raw:
            try:
                ports.append(int(item))
            except (TypeError, ValueError):
                continue
        return ports

    def _kill_pidfile(self, pid_path: str, *, label: str) -> None:
        if not os.path.isfile(pid_path):
            return
        try:
            with open(pid_path, "r", encoding="utf-8") as handle:
                pid_text = handle.read().strip()
            pid = int(pid_text)
        except (OSError, ValueError) as exc:
            logger.debug(
                "egress_enforcer.pidfile_unreadable",
                extra={"label": label, "path": pid_path, "error": str(exc)},
            )
            self._silent_unlink(pid_path)
            return
        try:
            os.kill(pid, 15)  # SIGTERM
        except ProcessLookupError:
            pass
        except OSError as exc:
            logger.warning(
                "egress_enforcer.kill_failed",
                extra={"label": label, "pid": pid, "error": str(exc)},
            )
        self._silent_unlink(pid_path)

    @staticmethod
    def _silent_unlink(path: str) -> None:
        try:
            if os.path.exists(path):
                os.unlink(path)
        except OSError:
            pass
