"""Zeek-based pcap post-execution analyzer.

Runs ``zeek -r <pcap> local`` inside a scratch workdir, then parses the
tab-separated logs that Zeek emits (``conn.log``, ``dns.log``, ``http.log``,
``ssl.log``, ``files.log``) into structured Python dicts. Also derives
``IndicatorArtifact``-shaped dicts (deduped by value) for observed
destinations, DNS queries, HTTP URLs, and file hashes.

Every subprocess/parsing failure downgrades to an empty result. The runner
never raises.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)


# -- Log field definitions ---------------------------------------------------

# These are the default Zeek log headers; we also support dynamic header
# discovery via the ``#fields`` directive that every Zeek TSV file carries.
_EMPTY_RESULT: Dict[str, Any] = {
    "connections": [],
    "dns": [],
    "http": [],
    "ssl": [],
    "files": [],
    "summary": {
        "counts": {"connections": 0, "dns": 0, "http": 0, "ssl": 0, "files": 0},
        "uniq_dests": [],
        "notable_uris": [],
    },
}


def _env_dry_run_default() -> bool:
    val = os.environ.get("SHESHNAAG_ZEEK_DRY_RUN", "").strip().lower()
    return val in {"1", "true", "yes", "on"}


class ZeekRunner:
    """Subprocess wrapper around the ``zeek`` CLI."""

    def __init__(
        self,
        *,
        zeek_binary: Optional[str] = None,
        dry_run: Optional[bool] = None,
    ) -> None:
        self.zeek_binary = zeek_binary or os.environ.get("SHESHNAAG_ZEEK_BIN", "zeek")
        self.dry_run = _env_dry_run_default() if dry_run is None else bool(dry_run)

    # -- Health ---------------------------------------------------------------

    def _binary_path(self) -> Optional[str]:
        if os.path.isabs(self.zeek_binary) and os.path.exists(self.zeek_binary):
            return self.zeek_binary
        return shutil.which(self.zeek_binary)

    def health(self) -> Dict[str, Any]:
        path = self._binary_path()
        if not path:
            return {
                "tool": "zeek",
                "binary": self.zeek_binary,
                "resolved_path": None,
                "version": None,
                "healthy": False,
                "reason": "binary_not_found",
            }
        try:
            proc = subprocess.run(
                [path, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            raw = (proc.stdout or proc.stderr or "").strip().splitlines()
            version = raw[0] if raw else None
            healthy = proc.returncode == 0
            return {
                "tool": "zeek",
                "binary": self.zeek_binary,
                "resolved_path": path,
                "version": version,
                "healthy": healthy,
                "reason": None if healthy else f"exit_{proc.returncode}",
            }
        except (subprocess.SubprocessError, OSError) as exc:
            return {
                "tool": "zeek",
                "binary": self.zeek_binary,
                "resolved_path": path,
                "version": None,
                "healthy": False,
                "reason": f"probe_failed: {exc}",
            }

    # -- Execution ------------------------------------------------------------

    def run(self, *, pcap_path: str, workdir: Optional[str] = None) -> Dict[str, Any]:
        """Run Zeek over ``pcap_path`` and return parsed log dictionaries."""
        result: Dict[str, Any] = {
            "connections": [],
            "dns": [],
            "http": [],
            "ssl": [],
            "files": [],
            "summary": {
                "counts": {"connections": 0, "dns": 0, "http": 0, "ssl": 0, "files": 0},
                "uniq_dests": [],
                "notable_uris": [],
            },
        }
        if not pcap_path:
            logger.warning("zeek_runner: empty pcap_path")
            return result

        path = self._binary_path()
        if not path:
            logger.warning("zeek_runner: binary '%s' not found; returning empty result", self.zeek_binary)
            return result

        if not os.path.isfile(pcap_path):
            logger.warning("zeek_runner: pcap %s does not exist; returning empty result", pcap_path)
            return result

        owns_tempdir = workdir is None
        scratch = workdir or tempfile.mkdtemp(prefix="sheshnaag-zeek-")
        try:
            if not self.dry_run:
                try:
                    proc = subprocess.run(
                        [path, "-r", pcap_path, "local"],
                        capture_output=True,
                        text=True,
                        timeout=600,
                        cwd=scratch,
                    )
                    if proc.returncode != 0:
                        logger.warning(
                            "zeek_runner: zeek exited %s: %s",
                            proc.returncode,
                            (proc.stderr or "")[:500],
                        )
                        return result
                except subprocess.TimeoutExpired:
                    logger.warning("zeek_runner: zeek timed out for %s", pcap_path)
                    return result
                except (subprocess.SubprocessError, OSError) as exc:
                    logger.warning("zeek_runner: zeek spawn failed: %s", exc)
                    return result

            result["connections"] = _parse_zeek_log(os.path.join(scratch, "conn.log"))
            result["dns"] = _parse_zeek_log(os.path.join(scratch, "dns.log"))
            result["http"] = _parse_zeek_log(os.path.join(scratch, "http.log"))
            result["ssl"] = _parse_zeek_log(os.path.join(scratch, "ssl.log"))
            result["files"] = _parse_zeek_log(os.path.join(scratch, "files.log"))
            result["summary"] = _summarize(result)
            return result
        finally:
            if owns_tempdir:
                shutil.rmtree(scratch, ignore_errors=True)

    # -- Indicator extraction -------------------------------------------------

    def extract_indicators(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Flatten a parsed Zeek result into IndicatorArtifact-shaped dicts.

        Dedupes by ``(indicator_kind, value)``; last-write wins on confidence
        so later evidence (e.g. a resolved DNS response) can upgrade an
        earlier placeholder.
        """
        indicators: Dict[Tuple[str, str], Dict[str, Any]] = {}

        def _add(kind: str, value: Any, *, confidence: float, payload: Dict[str, Any]) -> None:
            if value is None:
                return
            svalue = str(value).strip()
            if not svalue or svalue in {"-", "0.0.0.0", "::", "127.0.0.1", "::1"}:
                return
            key = (kind, svalue)
            existing = indicators.get(key)
            if existing is None or confidence > existing.get("confidence", 0.0):
                indicators[key] = {
                    "indicator_kind": kind,
                    "value": svalue,
                    "source": "zeek",
                    "confidence": round(float(confidence), 3),
                    "payload": payload,
                }

        for conn in results.get("connections") or []:
            dest = conn.get("id.resp_h") or conn.get("resp_h")
            _add(
                "ip",
                dest,
                confidence=0.55,
                payload={
                    "kind": "connection",
                    "proto": conn.get("proto"),
                    "dest_port": conn.get("id.resp_p") or conn.get("resp_p"),
                    "service": conn.get("service"),
                },
            )

        for dns in results.get("dns") or []:
            _add(
                "domain",
                dns.get("query"),
                confidence=0.6,
                payload={
                    "kind": "dns_query",
                    "qtype": dns.get("qtype_name"),
                    "rcode": dns.get("rcode_name"),
                },
            )
            for rr in _split_values(dns.get("answers")):
                # Heuristic: IPv4/IPv6 literals go in as ip, everything else as domain.
                if _looks_like_ip(rr):
                    _add("ip", rr, confidence=0.7, payload={"kind": "dns_answer", "query": dns.get("query")})
                else:
                    _add("domain", rr, confidence=0.55, payload={"kind": "dns_answer", "query": dns.get("query")})

        for http in results.get("http") or []:
            host = http.get("host")
            uri = http.get("uri")
            if host and uri:
                scheme = "http"
                _add(
                    "url",
                    f"{scheme}://{host}{uri}",
                    confidence=0.6,
                    payload={
                        "kind": "http_request",
                        "method": http.get("method"),
                        "status_code": http.get("status_code"),
                        "user_agent": http.get("user_agent"),
                    },
                )
            if host:
                _add("domain", host, confidence=0.55, payload={"kind": "http_host"})

        for ssl in results.get("ssl") or []:
            sni = ssl.get("server_name")
            _add("domain", sni, confidence=0.6, payload={"kind": "tls_sni", "version": ssl.get("version")})

        for fobj in results.get("files") or []:
            for field, kind, conf in (
                ("md5", "file_hash_md5", 0.8),
                ("sha1", "file_hash_sha1", 0.85),
                ("sha256", "file_hash_sha256", 0.9),
            ):
                _add(
                    kind,
                    fobj.get(field),
                    confidence=conf,
                    payload={
                        "kind": "file_hash",
                        "mime_type": fobj.get("mime_type"),
                        "filename": fobj.get("filename"),
                    },
                )

        # Stable order: by kind, then value.
        return sorted(indicators.values(), key=lambda ind: (ind["indicator_kind"], ind["value"]))


# -- Parsing helpers ---------------------------------------------------------


def _parse_zeek_log(path: str) -> List[Dict[str, Any]]:
    """Parse a Zeek TSV log, honoring the ``#fields`` / ``#types`` headers."""
    if not os.path.isfile(path):
        return []
    rows: List[Dict[str, Any]] = []
    fields: List[str] = []
    separator = "\t"
    unset_field = "-"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if not line:
                    continue
                if line.startswith("#"):
                    body = line[1:]
                    # Directive and payload may be separated by either a space
                    # (``#separator \x09``) or the in-file separator itself
                    # (``#fields\tts\tuid\t...``). Split on whichever delimiter
                    # appears first.
                    space_idx = body.find(" ")
                    sep_idx = body.find(separator) if separator else -1
                    if space_idx == -1:
                        split_idx = sep_idx
                    elif sep_idx == -1:
                        split_idx = space_idx
                    else:
                        split_idx = min(space_idx, sep_idx)
                    if split_idx == -1:
                        directive, payload = body, ""
                    else:
                        directive, payload = body[:split_idx], body[split_idx + 1 :]
                    directive = directive.strip().lower()
                    if directive == "separator":
                        sep = payload.strip()
                        if sep.startswith("\\x"):
                            try:
                                separator = bytes.fromhex(sep[2:]).decode("latin-1")
                            except ValueError:
                                separator = "\t"
                        elif sep:
                            separator = sep
                    elif directive == "unset_field":
                        unset_field = payload.strip() or "-"
                    elif directive == "fields":
                        fields = [p for p in payload.strip().split(separator) if p]
                    continue
                if not fields:
                    continue
                parts = line.split(separator)
                if len(parts) < len(fields):
                    parts += [unset_field] * (len(fields) - len(parts))
                row: Dict[str, Any] = {}
                for name, value in zip(fields, parts):
                    if value == unset_field or value == "(empty)":
                        row[name] = None
                    else:
                        row[name] = value
                rows.append(row)
    except OSError as exc:
        logger.warning("zeek_runner: failed to read %s: %s", path, exc)
        return []
    return rows


def _summarize(results: Dict[str, Any]) -> Dict[str, Any]:
    counts = {
        "connections": len(results.get("connections") or []),
        "dns": len(results.get("dns") or []),
        "http": len(results.get("http") or []),
        "ssl": len(results.get("ssl") or []),
        "files": len(results.get("files") or []),
    }
    uniq_dests: List[str] = []
    seen: set[str] = set()
    for conn in results.get("connections") or []:
        dest = conn.get("id.resp_h") or conn.get("resp_h")
        if dest and dest not in seen:
            seen.add(dest)
            uniq_dests.append(dest)
    notable: List[str] = []
    for http in results.get("http") or []:
        host = http.get("host")
        uri = http.get("uri") or ""
        if host:
            composed = f"http://{host}{uri}" if uri else f"http://{host}"
            if composed not in notable:
                notable.append(composed)
    return {
        "counts": counts,
        "uniq_dests": uniq_dests,
        "notable_uris": notable[:50],
    }


def _split_values(raw: Any) -> Iterable[str]:
    if raw is None:
        return ()
    if isinstance(raw, list):
        return [str(item) for item in raw if item not in (None, "-", "")]
    text = str(raw)
    if not text or text == "-":
        return ()
    return [piece.strip() for piece in text.split(",") if piece.strip() and piece.strip() != "-"]


def _looks_like_ip(value: str) -> bool:
    if not value:
        return False
    if value.count(".") == 3 and all(seg.isdigit() for seg in value.split(".")):
        try:
            return all(0 <= int(seg) <= 255 for seg in value.split("."))
        except ValueError:
            return False
    if ":" in value and all(ch in "0123456789abcdefABCDEF:" for ch in value):
        return True
    return False
