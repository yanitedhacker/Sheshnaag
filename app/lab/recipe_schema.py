"""
Formal recipe content schema validation, linting, revision diffing, and sign-off policy.

Aligned with lab recipe content shape from sheshnaag_service._normalize_recipe_content.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KNOWN_COLLECTORS: FrozenSet[str] = frozenset(
    {
        "process_tree",
        "package_inventory",
        "file_diff",
        "network_metadata",
        "service_logs",
        "tracee_events",
        "osquery_snapshot",
        "pcap",
        "falco_events",
        "tetragon_events",
    }
)

VALID_PROVIDERS: FrozenSet[str] = frozenset({"docker_kali", "lima"})
VALID_IMAGE_PROFILES: FrozenSet[str] = frozenset({"baseline", "osquery_capable", "tracee_capable", "secure_lima"})
VALID_LAUNCH_MODES: FrozenSet[str] = frozenset({"dry_run", "simulated", "execute"})

VALID_TEARDOWN_MODES: FrozenSet[str] = frozenset(
    {
        "destroy_immediately",
        "retain_exports_only",
        "retain_workspace_until_review",
    }
)

VALID_WORKSPACE_RETENTION: FrozenSet[str] = frozenset(VALID_TEARDOWN_MODES)

VALID_RISK_LEVELS: FrozenSet[str] = frozenset({"standard", "sensitive", "high"})

DANGEROUS_CAPABILITIES: FrozenSet[str] = frozenset(
    {
        "SYS_ADMIN",
        "NET_RAW",
        "NET_ADMIN",
        "SYS_MODULE",
        "SYS_PTRACE",
        "DAC_OVERRIDE",
        "SYS_BOOT",
        "LINUX_IMMUTABLE",
    }
)

RESTRICTED_CAPABILITIES_FOR_SIGNOFF: FrozenSet[str] = frozenset(
    {
        "SYS_ADMIN",
        "NET_RAW",
        "NET_ADMIN",
        "SYS_MODULE",
        "BPF",
        "SYSLOG",
    }
)

POLICY_RELEVANT_PREFIXES: Tuple[str, ...] = (
    "provider",
    "image_profile",
    "execution_policy",
    "risk_level",
    "requires_acknowledgement",
    "network_policy",
    "teardown_policy",
    "collectors",
    "cap_add",
    "mounts",
    "workspace_retention",
    "user",
)

DEFAULT_ALLOWED_HOST_PATH_ROOTS: FrozenSet[str] = frozenset({"/tmp", "/var/tmp"})

BLOCKED_HOST_PATHS: FrozenSet[str] = frozenset(
    {
        "/",
        "/run/docker.sock",
        "/var/run/docker.sock",
    }
)

BLOCKED_HOST_PREFIXES: Tuple[str, ...] = (
    "/Applications",
    "/Library",
    "/System",
    "/Users",
    "/bin",
    "/dev",
    "/etc",
    "/home",
    "/opt/homebrew",
    "/private",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/sys",
    "/usr",
    "/var/run",
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ValidationResult:
    valid: bool
    errors: List[str]
    warnings: List[str]


@dataclass
class LintResult:
    errors: List[str]
    warnings: List[str]
    has_blocking_errors: bool


@dataclass
class RecipeDiff:
    changes: List[Dict[str, Any]]
    policy_changes: List[Dict[str, Any]]
    risk_level_changed: bool
    collector_changes: bool
    network_changes: bool
    human_readable: str

    def to_dict(self) -> Dict[str, Any]:
        """Machine-readable summary of the diff."""
        return {
            "changes": list(self.changes),
            "policy_changes": list(self.policy_changes),
            "risk_level_changed": self.risk_level_changed,
            "collector_changes": self.collector_changes,
            "network_changes": self.network_changes,
            "human_readable": self.human_readable,
        }


@dataclass
class SignOffRequirement:
    required_approvals: int
    restricted_caps_present: List[str]
    eligible_roles: List[str]
    acknowledgement_text: str


@dataclass
class AcknowledgementRecord:
    """Who acknowledged which text and when (ISO 8601 UTC)."""

    party: str
    acknowledgement_text: str
    acknowledged_at: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_policy_field(field_path: str) -> bool:
    return any(field_path == p or field_path.startswith(f"{p}.") for p in POLICY_RELEVANT_PREFIXES)


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _normalize_str_list(items: Any, label: str) -> Tuple[Optional[List[str]], Optional[str]]:
    if not isinstance(items, list):
        return None, f"{label} must be a list"
    out: List[str] = []
    for i, item in enumerate(items):
        if not isinstance(item, str):
            return None, f"{label}[{i}] must be a string"
        out.append(item)
    return out, None


def _normalized_host_path(value: str) -> str:
    return os.path.normpath(value.strip())


def _allowed_host_roots() -> FrozenSet[str]:
    configured = os.environ.get("SHESHNAAG_ALLOWED_HOST_PATH_ROOTS", "")
    roots = {
        _normalized_host_path(root)
        for root in configured.split(",")
        if root.strip()
    }
    return frozenset(DEFAULT_ALLOWED_HOST_PATH_ROOTS | roots)


def _path_within_root(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _validate_allowed_host_path(path_value: Any, label: str) -> Optional[str]:
    if not isinstance(path_value, str):
        return f"{label} must be a string path"

    path = _normalized_host_path(path_value)
    if not path.startswith("/"):
        return f"{label} must be an absolute path"
    if path in BLOCKED_HOST_PATHS:
        return f"{label} {path!r} is blocked by Sheshnaag host safety policy"
    if any(path == prefix or path.startswith(f"{prefix}/") for prefix in BLOCKED_HOST_PREFIXES):
        return f"{label} {path!r} is host-sensitive and cannot be mounted or copied into a lab"

    allowed_roots = sorted(_allowed_host_roots())
    if not any(_path_within_root(path, root) for root in allowed_roots):
        return (
            f"{label} {path!r} is outside the allowed host path roots {allowed_roots}; "
            "set SHESHNAAG_ALLOWED_HOST_PATH_ROOTS for additional approved roots"
        )
    return None


# ---------------------------------------------------------------------------
# WS5-T1: RecipeSchemaValidator
# ---------------------------------------------------------------------------


class RecipeSchemaValidator:
    """Blocking schema checks for recipe content dicts."""

    def validate(self, content: Mapping[str, Any]) -> ValidationResult:
        errors: List[str] = []
        warnings: List[str] = []

        if not isinstance(content, Mapping):
            return ValidationResult(valid=False, errors=["Recipe content must be a mapping"], warnings=[])

        # base_image
        bi = content.get("base_image")
        if bi is None:
            errors.append("Missing required field 'base_image'")
        elif not isinstance(bi, str):
            errors.append("'base_image' must be a string")
        elif not bi.strip():
            errors.append("'base_image' must be a non-empty string")

        provider = content.get("provider", "docker_kali")
        if provider is not None:
            if not isinstance(provider, str):
                errors.append("'provider' must be a string when present")
            elif provider not in VALID_PROVIDERS:
                errors.append(f"Invalid provider {provider!r}; must be one of {sorted(VALID_PROVIDERS)}")

        image_profile = content.get("image_profile")
        if image_profile is not None:
            if not isinstance(image_profile, str):
                errors.append("'image_profile' must be a string when present")
            elif image_profile not in VALID_IMAGE_PROFILES:
                errors.append(f"Invalid image_profile {image_profile!r}; must be one of {sorted(VALID_IMAGE_PROFILES)}")

        # command
        cmd = content.get("command")
        if cmd is None:
            errors.append("Missing required field 'command'")
        elif not isinstance(cmd, list):
            errors.append("'command' must be a list of strings")
        elif len(cmd) == 0:
            errors.append("'command' must be a non-empty list of strings")
        else:
            for i, part in enumerate(cmd):
                if not isinstance(part, str):
                    errors.append(f"'command[{i}]' must be a string")
                    break

        # network_policy
        np = content.get("network_policy")
        if np is None:
            errors.append("Missing required field 'network_policy'")
        elif not isinstance(np, dict):
            errors.append("'network_policy' must be an object with 'allow_egress_hosts'")
        else:
            if "allow_egress_hosts" not in np:
                errors.append("'network_policy' must contain key 'allow_egress_hosts'")
            else:
                hosts = np["allow_egress_hosts"]
                if not isinstance(hosts, list):
                    errors.append("'network_policy.allow_egress_hosts' must be a list")
                else:
                    for i, h in enumerate(hosts):
                        if not isinstance(h, str):
                            errors.append(f"'network_policy.allow_egress_hosts[{i}]' must be a string")
                            break

        # collectors
        coll = content.get("collectors")
        if coll is None:
            errors.append("Missing required field 'collectors'")
        elif not isinstance(coll, list):
            errors.append("'collectors' must be a non-empty list of known collector names")
        elif len(coll) == 0:
            errors.append("'collectors' must be a non-empty list")
        else:
            seen: set[str] = set()
            for i, name in enumerate(coll):
                if not isinstance(name, str):
                    errors.append(f"'collectors[{i}]' must be a string")
                    break
                if name not in KNOWN_COLLECTORS:
                    errors.append(
                        f"Unknown collector {name!r}; expected one of {sorted(KNOWN_COLLECTORS)}"
                    )
                if name in seen:
                    warnings.append(f"Duplicate collector entry {name!r} at index {i}")
                seen.add(name)
            if "pcap" in seen and provider != "lima":
                errors.append("Collector 'pcap' is restricted to secure-mode Lima recipes.")
            if "tracee_events" in seen and image_profile not in (None, "tracee_capable"):
                warnings.append("tracee_events is most reliable with image_profile='tracee_capable'.")

        # teardown_policy
        tp = content.get("teardown_policy")
        if tp is None:
            errors.append("Missing required field 'teardown_policy'")
        elif not isinstance(tp, dict):
            errors.append("'teardown_policy' must be an object")
        else:
            mode = tp.get("mode")
            if mode is None:
                errors.append("'teardown_policy.mode' is required")
            elif mode not in VALID_TEARDOWN_MODES:
                errors.append(
                    f"Invalid teardown_policy.mode {mode!r}; must be one of {sorted(VALID_TEARDOWN_MODES)}"
                )
            ew = tp.get("ephemeral_workspace")
            if ew is not None and not isinstance(ew, bool):
                errors.append("'teardown_policy.ephemeral_workspace' must be a boolean when present")

        # risk_level & requires_acknowledgement
        rl = content.get("risk_level")
        if rl is None:
            errors.append("Missing required field 'risk_level'")
        elif rl not in VALID_RISK_LEVELS:
            errors.append(f"Invalid risk_level {rl!r}; must be one of {sorted(VALID_RISK_LEVELS)}")

        ra = content.get("requires_acknowledgement")
        if ra is not None and not isinstance(ra, bool):
            errors.append("'requires_acknowledgement' must be a boolean when present")

        if rl in ("sensitive", "high"):
            if ra is not True:
                errors.append(
                    f"risk_level {rl!r} requires 'requires_acknowledgement' to be True"
                )

        execution_policy = content.get("execution_policy")
        secure_mode_required = False
        if execution_policy is not None:
            if not isinstance(execution_policy, dict):
                errors.append("'execution_policy' must be an object when present")
            else:
                secure_mode_required = bool(execution_policy.get("secure_mode_required"))
                preferred_provider = execution_policy.get("preferred_provider")
                if preferred_provider is not None and preferred_provider not in VALID_PROVIDERS:
                    errors.append(
                        f"Invalid execution_policy.preferred_provider {preferred_provider!r}; must be one of {sorted(VALID_PROVIDERS)}"
                    )
                allowed_modes = execution_policy.get("allowed_modes")
                if allowed_modes is not None:
                    if not isinstance(allowed_modes, list):
                        errors.append("'execution_policy.allowed_modes' must be a list when present")
                    else:
                        for i, mode in enumerate(allowed_modes):
                            if mode not in VALID_LAUNCH_MODES:
                                errors.append(
                                    f"'execution_policy.allowed_modes[{i}]' must be one of {sorted(VALID_LAUNCH_MODES)}"
                                )
                if "secure_mode_required" in execution_policy and not isinstance(
                    execution_policy.get("secure_mode_required"), bool
                ):
                    errors.append("'execution_policy.secure_mode_required' must be a boolean when present")

        if secure_mode_required and provider != "lima":
            errors.append("secure-mode-required recipes must use provider 'lima'")

        # mounts
        if "mounts" in content:
            mounts = content["mounts"]
            if mounts is None:
                errors.append("'mounts' cannot be null when present")
            elif not isinstance(mounts, list):
                errors.append("'mounts' must be a list of mount objects")
            else:
                mount_policy = content.get("mount_write_policy")
                for i, m in enumerate(mounts):
                    if not isinstance(m, dict):
                        errors.append(f"'mounts[{i}]' must be an object with 'source' and 'target'")
                        continue
                    if "source" not in m:
                        errors.append(f"'mounts[{i}]' missing required key 'source'")
                    else:
                        mount_err = _validate_allowed_host_path(m.get("source"), f"'mounts[{i}].source'")
                        if mount_err:
                            errors.append(mount_err)
                    if "target" not in m:
                        errors.append(f"'mounts[{i}]' missing required key 'target'")
                    elif not isinstance(m.get("target"), str) or not str(m.get("target")).startswith("/"):
                        errors.append(f"'mounts[{i}].target' must be an absolute container path")
                    read_only = m.get("read_only", True)
                    if not isinstance(read_only, bool):
                        errors.append(f"'mounts[{i}].read_only' must be a boolean when present")
                    elif read_only is not True:
                        if not isinstance(mount_policy, dict):
                            errors.append(
                                f"'mounts[{i}]' is writable; add 'mount_write_policy' with explicit approval metadata"
                            )
                        elif mount_policy.get("approved") is not True or not isinstance(
                            mount_policy.get("approved_by"), str
                        ):
                            errors.append(
                                f"'mounts[{i}]' is writable; 'mount_write_policy.approved=True' and "
                                "'mount_write_policy.approved_by' are required"
                            )

        # artifact_inputs / input_artifacts
        artifact_inputs = content.get("artifact_inputs", content.get("input_artifacts"))
        if artifact_inputs is not None:
            if not isinstance(artifact_inputs, list):
                errors.append("'artifact_inputs' must be a list of input artifact objects when present")
            else:
                for i, artifact in enumerate(artifact_inputs):
                    if not isinstance(artifact, dict):
                        errors.append(f"'artifact_inputs[{i}]' must be an object")
                        continue
                    if "source_path" not in artifact:
                        errors.append(f"'artifact_inputs[{i}]' missing required key 'source_path'")
                    else:
                        source_err = _validate_allowed_host_path(
                            artifact.get("source_path"),
                            f"'artifact_inputs[{i}].source_path'",
                        )
                        if source_err:
                            errors.append(source_err)
                    name = artifact.get("name")
                    if name is not None and not isinstance(name, str):
                        errors.append(f"'artifact_inputs[{i}].name' must be a string when present")
                    destination = artifact.get("destination")
                    if destination is not None and (
                        not isinstance(destination, str) or not destination.startswith("/")
                    ):
                        errors.append(
                            f"'artifact_inputs[{i}].destination' must be an absolute container path when present"
                        )
                    expected_sha256 = artifact.get("sha256") or artifact.get("expected_sha256")
                    if expected_sha256 is not None:
                        if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
                            errors.append(
                                f"'artifact_inputs[{i}].sha256' must be a 64-character hex digest when present"
                            )
                        else:
                            lowered = expected_sha256.lower()
                            if any(ch not in "0123456789abcdef" for ch in lowered):
                                errors.append(
                                    f"'artifact_inputs[{i}].sha256' must be a lowercase or uppercase hex digest"
                                )

        # workspace_retention
        if "workspace_retention" in content and content["workspace_retention"] is not None:
            wr = content["workspace_retention"]
            if not isinstance(wr, str):
                errors.append("'workspace_retention' must be a string when present")
            elif wr not in VALID_WORKSPACE_RETENTION:
                errors.append(
                    f"Invalid workspace_retention {wr!r}; must be one of {sorted(VALID_WORKSPACE_RETENTION)}"
                )

        # Optional evidence baselines (WS6): typed when present
        fmb = content.get("file_manifest_baseline")
        if fmb is not None:
            if not isinstance(fmb, list):
                errors.append("'file_manifest_baseline' must be a list of path strings when present")
            else:
                for i, p in enumerate(fmb):
                    if not isinstance(p, str):
                        errors.append(f"'file_manifest_baseline[{i}]' must be a string")
                        break
        pkgb = content.get("package_baseline")
        if pkgb is not None:
            if not isinstance(pkgb, list):
                errors.append("'package_baseline' must be a list of objects when present")
            else:
                for i, row in enumerate(pkgb):
                    if not isinstance(row, dict):
                        errors.append(f"'package_baseline[{i}]' must be an object with 'name'")
                        break
                    if "name" not in row:
                        errors.append(f"'package_baseline[{i}]' missing required key 'name'")
                        break
        logs = content.get("log_sources")
        if logs is not None:
            if not isinstance(logs, list):
                errors.append("'log_sources' must be a list when present")
            else:
                for i, entry in enumerate(logs):
                    if isinstance(entry, str):
                        continue
                    if isinstance(entry, dict) and entry.get("path"):
                        continue
                    errors.append(f"'log_sources[{i}]' must be a string path or object with 'path'")
                    break

        # Optional fields: cap_add, user, workdir — light type checks (warnings)
        if "cap_add" in content:
            caps = content["cap_add"]
            if caps is not None:
                _, err = _normalize_str_list(caps, "cap_add")
                if err:
                    warnings.append(err)

        valid = len(errors) == 0
        return ValidationResult(valid=valid, errors=errors, warnings=warnings)


# ---------------------------------------------------------------------------
# WS5-T2: RecipeLinter
# ---------------------------------------------------------------------------


class RecipeLinter:
    """Non-schema lint rules: risky configs, combinations, and policy hints."""

    def __init__(self, expected_distro: Optional[str] = None) -> None:
        self.expected_distro = (expected_distro or "").strip().lower() or None

    def lint(self, content: Mapping[str, Any]) -> LintResult:
        errors: List[str] = []
        warnings: List[str] = []

        bi = content.get("base_image")
        if bi is None or (isinstance(bi, str) and not bi.strip()):
            errors.append("Lint: recipe has no usable base image")

        cmd = content.get("command")
        if cmd is None or (isinstance(cmd, list) and len(cmd) == 0):
            errors.append("Lint: recipe has no command")

        # cap_add
        caps_raw = content.get("cap_add")
        if isinstance(caps_raw, list):
            for cap in caps_raw:
                if isinstance(cap, str) and cap.upper() in DANGEROUS_CAPABILITIES:
                    warnings.append(
                        f"Risky capability requested: {cap!r} (elevates container breakout / network risk)"
                    )

        # Unsupported / weak collector combinations
        coll = content.get("collectors")
        if isinstance(coll, list):
            names = [c for c in coll if isinstance(c, str)]
            name_set = set(names)
            if len(names) != len(name_set):
                warnings.append("Collectors list contains duplicates; dedupe for predictable telemetry")
            if "tracee_events" in name_set and "process_tree" not in name_set:
                warnings.append(
                    "Collector combination: 'tracee_events' without 'process_tree' may miss baseline process context"
                )
            if "network_metadata" in name_set and "file_diff" not in name_set:
                warnings.append(
                    "Collector combination: 'network_metadata' without 'file_diff' limits filesystem drift correlation"
                )
            if "tracee_events" in name_set and content.get("image_profile") not in (None, "tracee_capable"):
                warnings.append("Tracee support should use image_profile='tracee_capable'.")
            if "pcap" in name_set and content.get("provider", "docker_kali") != "lima":
                errors.append("PCAP is restricted to secure-mode Lima recipes.")

        # Distro / template vs image
        if self.expected_distro and isinstance(bi, str) and bi.strip():
            img_l = bi.lower()
            if self.expected_distro == "kali" and "kali" not in img_l:
                warnings.append(
                    f"Template/distro mismatch: expected Kali-related image, got {bi!r}"
                )
            elif self.expected_distro == "ubuntu" and "ubuntu" not in img_l:
                warnings.append(
                    f"Template/distro mismatch: expected Ubuntu-related image, got {bi!r}"
                )
            elif self.expected_distro == "debian" and "debian" not in img_l and "ubuntu" not in img_l:
                warnings.append(
                    f"Template/distro mismatch: expected Debian-family image, got {bi!r}"
                )

        # Egress without network collector
        np = content.get("network_policy")
        coll_list = content.get("collectors")
        if isinstance(np, dict) and isinstance(coll_list, list):
            hosts = np.get("allow_egress_hosts")
            if isinstance(hosts, list) and any(isinstance(h, str) and h.strip() for h in hosts):
                if not any(c == "network_metadata" for c in coll_list if isinstance(c, str)):
                    warnings.append(
                        "network_policy allows egress hosts but 'network_metadata' is not in collectors"
                    )

        # High risk: mounts should be read-only where applicable
        rl = content.get("risk_level")
        if rl == "high":
            mounts = content.get("mounts")
            if mounts is None:
                warnings.append(
                    "High risk_level: no 'mounts' defined — cannot verify read-only volume restrictions"
                )
            elif isinstance(mounts, list) and len(mounts) == 0:
                warnings.append(
                    "High risk_level: empty 'mounts' — confirm workspace isolation is intentional"
                )
            elif isinstance(mounts, list):
                for i, m in enumerate(mounts):
                    if isinstance(m, dict) and m.get("read_only") is not True:
                        warnings.append(
                            f"High risk_level: mounts[{i}] is not read_only=True — host write exposure"
                        )

        execution_policy = content.get("execution_policy")
        if isinstance(execution_policy, dict):
            if execution_policy.get("secure_mode_required") is True and content.get("provider", "docker_kali") != "lima":
                errors.append("Secure-mode-required execution policy conflicts with a non-Lima provider.")

        has_blocking_errors = len(errors) > 0
        return LintResult(errors=errors, warnings=warnings, has_blocking_errors=has_blocking_errors)


# ---------------------------------------------------------------------------
# WS5-T3: RecipeDiffEngine
# ---------------------------------------------------------------------------


class RecipeDiffEngine:
    """Field-level diff between two recipe content revisions."""

    _TOP_KEYS: Tuple[str, ...] = (
        "base_image",
        "provider",
        "image_profile",
        "execution_policy",
        "command",
        "network_policy",
        "collectors",
        "teardown_policy",
        "risk_level",
        "requires_acknowledgement",
        "mounts",
        "cap_add",
        "user",
        "workdir",
        "workspace_retention",
    )

    def diff(self, old_content: Mapping[str, Any], new_content: Mapping[str, Any]) -> RecipeDiff:
        changes: List[Dict[str, Any]] = []

        def add_change(path: str, old_v: Any, new_v: Any) -> None:
            pr = _is_policy_field(path)
            changes.append(
                {
                    "field": path,
                    "old_value": old_v,
                    "new_value": new_v,
                    "is_policy_relevant": pr,
                }
            )

        all_keys = set(old_content.keys()) | set(new_content.keys()) | set(self._TOP_KEYS)

        for key in sorted(all_keys):
            old_v = old_content.get(key, _MISSING)
            new_v = new_content.get(key, _MISSING)
            if old_v is _MISSING and new_v is _MISSING:
                continue
            if key == "network_policy":
                self._diff_mapping_nested(
                    "network_policy", old_v, new_v, {"allow_egress_hosts"}, add_change
                )
            elif key == "teardown_policy":
                self._diff_mapping_nested(
                    "teardown_policy", old_v, new_v, {"mode", "ephemeral_workspace"}, add_change
                )
            elif key in ("command", "collectors", "cap_add"):
                self._diff_sequence(key, old_v, new_v, add_change)
            elif key == "mounts":
                self._diff_mounts(old_v, new_v, add_change)
            else:
                if old_v != new_v:
                    if _stable_json(old_v) != _stable_json(new_v):
                        add_change(key, old_v if old_v is not _MISSING else None, new_v if new_v is not _MISSING else None)

        policy_changes = [c for c in changes if c.get("is_policy_relevant")]
        risk_level_changed = any(c["field"] == "risk_level" for c in changes)
        collector_changes = any(c["field"] == "collectors" for c in changes)
        network_changes = any(c["field"].startswith("network_policy") for c in changes)

        human = self._render_markdown(changes, policy_changes, risk_level_changed, collector_changes, network_changes)

        return RecipeDiff(
            changes=changes,
            policy_changes=policy_changes,
            risk_level_changed=risk_level_changed,
            collector_changes=collector_changes,
            network_changes=network_changes,
            human_readable=human,
        )

    def _diff_mapping_nested(
        self,
        prefix: str,
        old_v: Any,
        new_v: Any,
        keys: FrozenSet[str],
        add_change,
    ) -> None:
        if not isinstance(old_v, dict) and old_v is not _MISSING:
            add_change(prefix, old_v, new_v if new_v is not _MISSING else None)
            return
        if not isinstance(new_v, dict) and new_v is not _MISSING:
            add_change(prefix, old_v if old_v is not _MISSING else None, new_v)
            return
        od = old_v if isinstance(old_v, dict) else {}
        nd = new_v if isinstance(new_v, dict) else {}
        for k in sorted(keys | set(od.keys()) | set(nd.keys())):
            o, n = od.get(k, _MISSING), nd.get(k, _MISSING)
            if o != n and _stable_json(o) != _stable_json(n):
                add_change(f"{prefix}.{k}", o if o is not _MISSING else None, n if n is not _MISSING else None)

    def _diff_sequence(self, key: str, old_v: Any, new_v: Any, add_change) -> None:
        o_list = old_v if isinstance(old_v, list) else ([] if old_v is _MISSING else old_v)
        n_list = new_v if isinstance(new_v, list) else ([] if new_v is _MISSING else new_v)
        if not isinstance(o_list, list):
            add_change(key, old_v, new_v)
            return
        if not isinstance(n_list, list):
            add_change(key, old_v, new_v)
            return
        if o_list != n_list:
            add_change(key, o_list if old_v is not _MISSING else None, n_list if new_v is not _MISSING else None)

    def _diff_mounts(self, old_v: Any, new_v: Any, add_change) -> None:
        if old_v == new_v:
            return
        if not isinstance(old_v, list) and old_v is not _MISSING:
            add_change("mounts", old_v, new_v)
            return
        if not isinstance(new_v, list) and new_v is not _MISSING:
            add_change("mounts", old_v, new_v)
            return
        ol = old_v if isinstance(old_v, list) else []
        nl = new_v if isinstance(new_v, list) else []
        if ol != nl:
            add_change("mounts", ol if old_v is not _MISSING else None, nl if new_v is not _MISSING else None)

    def _render_markdown(
        self,
        changes: List[Dict[str, Any]],
        policy_changes: List[Dict[str, Any]],
        risk_level_changed: bool,
        collector_changes: bool,
        network_changes: bool,
    ) -> str:
        lines: List[str] = ["## Recipe revision diff", ""]
        lines.append("### Summary")
        lines.append(f"- **Risk level changed:** {'yes' if risk_level_changed else 'no'}")
        lines.append(f"- **Collectors changed:** {'yes' if collector_changes else 'no'}")
        lines.append(f"- **Network policy changed:** {'yes' if network_changes else 'no'}")
        lines.append(f"- **Total field changes:** {len(changes)}")
        lines.append(f"- **Policy-relevant changes:** {len(policy_changes)}")
        lines.append("")
        lines.append("### Policy-relevant changes")
        if not policy_changes:
            lines.append("_None_")
        else:
            for c in policy_changes:
                lines.append(
                    f"- **`{c['field']}`:** `{c['old_value']!r}` → `{c['new_value']!r}`"
                )
        lines.append("")
        lines.append("### All changes")
        if not changes:
            lines.append("_No differences_")
        else:
            for c in changes:
                flag = " _(policy)_" if c.get("is_policy_relevant") else ""
                lines.append(
                    f"- **`{c['field']}`**{flag}: `{c['old_value']!r}` → `{c['new_value']!r}`"
                )
        return "\n".join(lines)


_MISSING = object()


# ---------------------------------------------------------------------------
# WS5-T4: SignOffPolicy
# ---------------------------------------------------------------------------


DEFAULT_ACKNOWLEDGEMENT_TEMPLATE = (
    "I confirm that I understand the risk classification ({risk_level}), "
    "the container configuration (including any elevated capabilities: {caps_summary}), "
    "and accept responsibility for executing this lab recipe under tenant policy."
)


class SignOffPolicy:
    """
    Sign-off counts by risk, extra requirements for restricted capabilities,
    role eligibility (high risk), and optional acknowledgement ledger.
    """

    APPROVALS_BY_RISK: Dict[str, int] = {"standard": 1, "sensitive": 1, "high": 2}

    HIGH_RISK_ELIGIBLE_ROLES: Tuple[str, ...] = ("lead", "security")
    DEFAULT_ELIGIBLE_ROLES: Tuple[str, ...] = ("lead", "security", "researcher")

    EXTRA_APPROVALS_FOR_RESTRICTED_CAP: int = 1

    def __init__(self) -> None:
        self._approvals_by_risk: Dict[str, int] = dict(SignOffPolicy.APPROVALS_BY_RISK)
        self._acknowledgements: List[AcknowledgementRecord] = []

    @property
    def restricted_capabilities(self) -> FrozenSet[str]:
        return RESTRICTED_CAPABILITIES_FOR_SIGNOFF

    def register_acknowledgement(
        self,
        party: str,
        acknowledgement_text: str,
        acknowledged_at: Optional[datetime] = None,
    ) -> AcknowledgementRecord:
        """Record who acknowledged what and when (stored on this policy instance)."""
        when = acknowledged_at or datetime.now(timezone.utc)
        ts = when.isoformat().replace("+00:00", "Z")
        rec = AcknowledgementRecord(party=party, acknowledgement_text=acknowledgement_text, acknowledged_at=ts)
        self._acknowledgements.append(rec)
        return rec

    @property
    def acknowledgements(self) -> List[AcknowledgementRecord]:
        return list(self._acknowledgements)

    def evaluate(
        self,
        risk_level: str,
        capabilities: Optional[Sequence[str]] = None,
        reviewer_role: Optional[str] = None,
    ) -> SignOffRequirement:
        """
        Compute required approvals, restricted caps hit, eligible reviewer roles,
        and the acknowledgement copy for this recipe.

        Compare ``reviewer_role`` to ``eligible_roles`` at the call site when
        enforcing approval authority.
        """
        if reviewer_role is not None and not isinstance(reviewer_role, str):
            raise TypeError("reviewer_role must be str or None")

        rl = (risk_level or "standard").lower()
        if rl not in VALID_RISK_LEVELS:
            rl = "standard"

        caps = [c for c in (capabilities or []) if isinstance(c, str)]
        caps_upper = [c.upper() for c in caps]
        restricted_hit = sorted({c for c in caps_upper if c in self.restricted_capabilities})

        base = self._approvals_by_risk.get(rl, 1)
        extra = self.EXTRA_APPROVALS_FOR_RESTRICTED_CAP if restricted_hit else 0
        required = base + extra

        if rl == "high":
            eligible = list(self.HIGH_RISK_ELIGIBLE_ROLES)
        else:
            eligible = list(self.DEFAULT_ELIGIBLE_ROLES)

        caps_summary = ", ".join(restricted_hit) if restricted_hit else "none flagged"
        ack = DEFAULT_ACKNOWLEDGEMENT_TEMPLATE.format(risk_level=rl, caps_summary=caps_summary)

        return SignOffRequirement(
            required_approvals=required,
            restricted_caps_present=restricted_hit,
            eligible_roles=eligible,
            acknowledgement_text=ack,
        )
