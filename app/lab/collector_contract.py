"""
Stable contract between Pod C (provider) and Pod D (collectors).

Collectors read run_context and provider_result-shaped dicts built by SheshnaagService.
Provider manifests are extended at apply-time with execution metadata.
"""

from __future__ import annotations

from typing import Any, Dict, Final, List

# Framework version bump when evidence payload shape changes materially.
COLLECTOR_FRAMEWORK_VERSION: Final[str] = "1.0.0"

# Default collector ordering when recipe omits the list (keep in sync with sheshnaag_service._normalize_recipe_content).
DEFAULT_RECIPE_COLLECTORS: Final[List[str]] = [
    "process_tree",
    "package_inventory",
    "file_diff",
    "network_metadata",
    "service_logs",
    "tracee_events",
]

# Manifest keys (plan dict persisted on LabRun.manifest)
MANIFEST_KEY_CONTAINER_ID: Final[str] = "container_id"
MANIFEST_KEY_HOST_WORKSPACE: Final[str] = "host_workspace"
MANIFEST_KEY_EFFECTIVE_NETWORK_POLICY: Final[str] = "effective_network_policy"
MANIFEST_KEY_NETWORK_MODE: Final[str] = "network_mode"
MANIFEST_KEY_ALLOW_EGRESS_HOSTS: Final[str] = "allow_egress_hosts"
MANIFEST_KEY_COLLECTORS: Final[str] = "collectors"
# Optional recipe hints copied into provider plan for diff-capable collectors (WS6)
MANIFEST_KEY_FILE_MANIFEST_BASELINE: Final[str] = "file_manifest_baseline"
MANIFEST_KEY_PACKAGE_BASELINE: Final[str] = "package_baseline"
MANIFEST_KEY_LOG_SOURCES: Final[str] = "log_sources"

# run_context keys (built in SheshnaagService._collect_and_generate)
RUN_CONTEXT_RUN_ID: Final[str] = "run_id"
RUN_CONTEXT_LAUNCH_MODE: Final[str] = "launch_mode"
RUN_CONTEXT_RECIPE_CONTENT: Final[str] = "recipe_content"
RUN_CONTEXT_CVE_ID: Final[str] = "cve_id"
RUN_CONTEXT_CANDIDATE: Final[str] = "candidate"
RUN_CONTEXT_TENANT_SLUG: Final[str] = "tenant_slug"
RUN_CONTEXT_ANALYST_NAME: Final[str] = "analyst_name"

# provider_result keys passed into collectors (superset of ProviderResult.to_dict)
PROVIDER_KEY_RUN_REF: Final[str] = "provider_run_ref"
PROVIDER_KEY_PLAN: Final[str] = "plan"
PROVIDER_KEY_STATE: Final[str] = "state"
PROVIDER_KEY_CONTAINER_ID: Final[str] = "container_id"
PROVIDER_KEY_ERROR: Final[str] = "error"


def build_provider_result_dict(
    *,
    provider_run_ref: str | None,
    plan: Dict[str, Any],
    state: str | None = None,
    container_id: str | None = None,
    error: str | None = None,
) -> Dict[str, Any]:
    """Normalized dict collectors receive (matches ProviderResult.to_dict() fields used by collectors)."""
    return {
        PROVIDER_KEY_RUN_REF: provider_run_ref or "",
        PROVIDER_KEY_PLAN: plan or {},
        PROVIDER_KEY_STATE: state or "",
        PROVIDER_KEY_CONTAINER_ID: container_id or (plan or {}).get(MANIFEST_KEY_CONTAINER_ID),
        PROVIDER_KEY_ERROR: error,
    }


def recipe_collector_names(recipe_content: Dict[str, Any]) -> List[str]:
    """Ordered collector list from recipe content (defaults applied upstream)."""
    raw = recipe_content.get(MANIFEST_KEY_COLLECTORS)
    if raw is None:
        return list(DEFAULT_RECIPE_COLLECTORS)
    if not isinstance(raw, list):
        return list(DEFAULT_RECIPE_COLLECTORS)
    names = [str(x) for x in raw]
    return names if names else list(DEFAULT_RECIPE_COLLECTORS)
