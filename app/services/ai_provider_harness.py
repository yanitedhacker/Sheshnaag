"""Guardrailed AI provider harness for V3 malware-lab workflows."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List


BLOCKED_PROMPT_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\bweaponi[sz]e\b",
        r"\bpublic[- ]target\b",
        r"\bcredential theft\b",
        r"\bcredential dump(?:ing)?\b",
        r"\bpersistence mechanism\b",
        r"\bpersistence\b.+\bmalware\b",
        r"\bphishing\b",
        r"\bmass scanning\b",
        r"\bexploit chain\b",
        r"\bturnkey exploit\b",
        r"\bprivilege escalation exploit\b",
        r"\bpayload delivery\b",
        r"\bransomware\b.+\bdeploy\b",
    ]
]

SUPPORTED_CAPABILITIES = {
    "summarize_evidence",
    "cluster_iocs",
    "draft_hypotheses",
    "generate_detection_candidates",
    "draft_mitigation",
    "draft_report_sections",
    "variant_diff_review",
}

DEFAULT_EXECUTION_TIMEOUT_SECONDS = 45


def _grounded_fallback_output(
    *,
    display_name: str,
    model_label: str,
    capability: str,
    prompt: str,
    grounding: Dict[str, Any],
    execution_status: str,
    execution_error: str | None = None,
) -> Dict[str, Any]:
    grounding_items = grounding.get("items") or []
    report_lines = [
        f"## {display_name} draft",
        "",
        f"- Capability: `{capability}`",
        f"- Model: `{model_label}`",
        f"- Grounding items: `{len(grounding_items)}`",
        f"- Execution status: `{execution_status}`",
        "",
        "### Analyst prompt",
        prompt.strip(),
        "",
        "### Grounded output",
        "This draft is restricted to supplied artifacts and must be reviewed before promotion.",
    ]
    if execution_error:
        report_lines.extend(["", "### Provider note", execution_error.strip()])
    if grounding_items:
        report_lines.extend(
            [
                "",
                "### Grounding summary",
                *[
                    f"- {item.get('label') or item.get('kind') or 'context'}: {str(item.get('summary') or item.get('value') or item)[:160]}"
                    for item in grounding_items[:8]
                ],
            ]
        )
    return {
        "output_markdown": "\n".join(report_lines),
        "output_payload": {
            "capability": capability,
            "grounding_count": len(grounding_items),
            "draft_only": True,
            "execution_status": execution_status,
            "execution_error": execution_error,
        },
    }


@dataclass(frozen=True)
class AIAdapter:
    provider_key: str
    provider_mode: str
    display_name: str
    model_label: str
    capabilities: List[str]
    requires_api_key: bool = False
    command_hint: str | None = None
    api_key_env: str | None = None
    api_url_env: str | None = None
    model_env: str | None = None
    timeout_seconds: int = DEFAULT_EXECUTION_TIMEOUT_SECONDS
    extra_metadata: Dict[str, Any] = field(default_factory=dict)

    def resolved_model_label(self) -> str:
        if self.model_env and os.getenv(self.model_env):
            return os.getenv(self.model_env, self.model_label)
        return self.model_label

    def _cli_health(self) -> Dict[str, Any]:
        command = os.getenv("SHESHNAAG_GOODBEAR_COMMAND", self.command_hint or "").strip()
        binary = shlex.split(command)[0] if command else None
        binary_path = shutil.which(binary) if binary else None
        healthy = bool(binary_path)
        return {
            "status": "available" if healthy else "unconfigured",
            "healthy": healthy,
            "binary": binary,
            "binary_path": binary_path,
            "command": command or None,
            "configuration_source": "SHESHNAAG_GOODBEAR_COMMAND" if os.getenv("SHESHNAAG_GOODBEAR_COMMAND") else "default",
        }

    def _api_health(self) -> Dict[str, Any]:
        api_key = os.getenv(self.api_key_env or "")
        api_url = os.getenv(self.api_url_env or "")
        model = os.getenv(self.model_env or "", self.model_label)
        missing = []
        if self.requires_api_key and not api_key:
            missing.append(self.api_key_env)
        if not api_url:
            missing.append(self.api_url_env)
        healthy = not missing
        return {
            "status": "available" if healthy else "unconfigured",
            "healthy": healthy,
            "api_url": api_url or None,
            "model": model,
            "missing_configuration": [item for item in missing if item],
        }

    def health(self) -> Dict[str, Any]:
        if self.provider_mode == "cli":
            return self._cli_health()
        if self.provider_mode == "api":
            return self._api_health()
        return {"status": "unknown", "healthy": False}

    def catalog_entry(self) -> Dict[str, Any]:
        health = self.health()
        return {
            "provider_key": self.provider_key,
            "provider_mode": self.provider_mode,
            "display_name": self.display_name,
            "model_label": self.resolved_model_label(),
            "capabilities": list(self.capabilities),
            "requires_api_key": self.requires_api_key,
            "command_hint": self.command_hint,
            "status": health.get("status"),
            "healthy": health.get("healthy", False),
            "health": health,
            **self.extra_metadata,
        }

    def _run_cli(self, *, capability: str, prompt: str, grounding: Dict[str, Any]) -> Dict[str, Any]:
        health = self._cli_health()
        if not health.get("healthy"):
            return {
                **_grounded_fallback_output(
                    display_name=self.display_name,
                    model_label=self.resolved_model_label(),
                    capability=capability,
                    prompt=prompt,
                    grounding=grounding,
                    execution_status="simulated_unconfigured",
                    execution_error="CLI provider is not installed or not configured on this host.",
                ),
                "execution": health,
            }

        payload = json.dumps(
            {
                "capability": capability,
                "prompt": prompt,
                "grounding": grounding,
                "draft_only": True,
            },
            sort_keys=True,
            default=str,
        )
        started = time.monotonic()
        try:
            proc = subprocess.run(
                shlex.split(health["command"]),
                input=payload,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            execution = {
                **health,
                "status": "degraded",
                "healthy": False,
                "error": str(exc),
            }
            return {
                **_grounded_fallback_output(
                    display_name=self.display_name,
                    model_label=self.resolved_model_label(),
                    capability=capability,
                    prompt=prompt,
                    grounding=grounding,
                    execution_status="simulated_error",
                    execution_error=str(exc),
                ),
                "execution": execution,
            }

        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        execution = {
            **health,
            "status": "available" if proc.returncode == 0 else "degraded",
            "healthy": proc.returncode == 0,
            "returncode": proc.returncode,
            "stderr": stderr or None,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        if proc.returncode != 0:
            return {
                **_grounded_fallback_output(
                    display_name=self.display_name,
                    model_label=self.resolved_model_label(),
                    capability=capability,
                    prompt=prompt,
                    grounding=grounding,
                    execution_status="simulated_cli_failure",
                    execution_error=stderr or "CLI provider returned a non-zero exit code.",
                ),
                "execution": execution,
            }
        try:
            parsed = json.loads(stdout) if stdout else {}
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict) and parsed.get("output_markdown"):
            return {
                "output_markdown": str(parsed["output_markdown"]),
                "output_payload": {
                    **(parsed.get("output_payload") or {}),
                    "draft_only": True,
                    "execution_status": "completed",
                },
                "execution": execution,
            }
        return {
            **_grounded_fallback_output(
                display_name=self.display_name,
                model_label=self.resolved_model_label(),
                capability=capability,
                prompt=prompt,
                grounding=grounding,
                execution_status="completed",
                execution_error=None,
            ),
            "output_markdown": stdout or _grounded_fallback_output(
                display_name=self.display_name,
                model_label=self.resolved_model_label(),
                capability=capability,
                prompt=prompt,
                grounding=grounding,
                execution_status="completed",
            )["output_markdown"],
            "execution": execution,
        }

    def _run_api(self, *, capability: str, prompt: str, grounding: Dict[str, Any]) -> Dict[str, Any]:
        health = self._api_health()
        if not health.get("healthy"):
            return {
                **_grounded_fallback_output(
                    display_name=self.display_name,
                    model_label=self.resolved_model_label(),
                    capability=capability,
                    prompt=prompt,
                    grounding=grounding,
                    execution_status="simulated_unconfigured",
                    execution_error="API provider is missing required configuration.",
                ),
                "execution": health,
            }

        request_body = json.dumps(
            {
                "provider_key": self.provider_key,
                "model": self.resolved_model_label(),
                "capability": capability,
                "prompt": prompt,
                "grounding": grounding,
                "draft_only": True,
            },
            sort_keys=True,
            default=str,
        ).encode("utf-8")
        req = urllib.request.Request(
            url=health["api_url"],
            data=request_body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {os.getenv(self.api_key_env or '', '')}",
            },
            method="POST",
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as response:  # noqa: S310
                body = response.read().decode("utf-8")
                status_code = response.getcode()
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            execution = {
                **health,
                "status": "degraded",
                "healthy": False,
                "error": str(exc),
            }
            return {
                **_grounded_fallback_output(
                    display_name=self.display_name,
                    model_label=self.resolved_model_label(),
                    capability=capability,
                    prompt=prompt,
                    grounding=grounding,
                    execution_status="simulated_error",
                    execution_error=str(exc),
                ),
                "execution": execution,
            }

        execution = {
            **health,
            "status": "available" if 200 <= status_code < 300 else "degraded",
            "healthy": 200 <= status_code < 300,
            "status_code": status_code,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict) and parsed.get("output_markdown"):
            return {
                "output_markdown": str(parsed["output_markdown"]),
                "output_payload": {
                    **(parsed.get("output_payload") or {}),
                    "draft_only": True,
                    "execution_status": "completed",
                },
                "execution": execution,
            }
        return {
            **_grounded_fallback_output(
                display_name=self.display_name,
                model_label=self.resolved_model_label(),
                capability=capability,
                prompt=prompt,
                grounding=grounding,
                execution_status="completed",
                execution_error=None,
            ),
            "output_markdown": body or _grounded_fallback_output(
                display_name=self.display_name,
                model_label=self.resolved_model_label(),
                capability=capability,
                prompt=prompt,
                grounding=grounding,
                execution_status="completed",
            )["output_markdown"],
            "execution": execution,
        }

    def run(self, *, capability: str, prompt: str, grounding: Dict[str, Any]) -> Dict[str, Any]:
        if self.provider_mode == "cli":
            return self._run_cli(capability=capability, prompt=prompt, grounding=grounding)
        if self.provider_mode == "api":
            return self._run_api(capability=capability, prompt=prompt, grounding=grounding)
        return {
            **_grounded_fallback_output(
                display_name=self.display_name,
                model_label=self.resolved_model_label(),
                capability=capability,
                prompt=prompt,
                grounding=grounding,
                execution_status="simulated_unknown_provider_mode",
            ),
            "execution": {"status": "unknown", "healthy": False},
        }


class AIProviderHarness:
    """Catalog and execute allowed AI provider drafts without side effects."""

    def __init__(self) -> None:
        self._providers = {
            "goodbear-cli": AIAdapter(
                provider_key="goodbear-cli",
                provider_mode="cli",
                display_name="Goodbear CLI",
                model_label="goodbear-desktop",
                capabilities=sorted(SUPPORTED_CAPABILITIES),
                command_hint="goodbear analyze --stdin",
                extra_metadata={"provider_family": "desktop_cli"},
            ),
            "openai-api": AIAdapter(
                provider_key="openai-api",
                provider_mode="api",
                display_name="OpenAI-Compatible API",
                model_label="frontier-api",
                capabilities=sorted(SUPPORTED_CAPABILITIES),
                requires_api_key=True,
                api_key_env="OPENAI_API_KEY",
                api_url_env="SHESHNAAG_OPENAI_API_URL",
                model_env="SHESHNAAG_OPENAI_MODEL",
                extra_metadata={"provider_family": "remote_api"},
            ),
            "anthropic-api": AIAdapter(
                provider_key="anthropic-api",
                provider_mode="api",
                display_name="Anthropic-Compatible API",
                model_label="frontier-api",
                capabilities=sorted(SUPPORTED_CAPABILITIES),
                requires_api_key=True,
                api_key_env="ANTHROPIC_API_KEY",
                api_url_env="SHESHNAAG_ANTHROPIC_API_URL",
                model_env="SHESHNAAG_ANTHROPIC_MODEL",
                extra_metadata={"provider_family": "remote_api"},
            ),
        }

    def list_providers(self) -> List[Dict[str, Any]]:
        return [adapter.catalog_entry() for adapter in self._providers.values()]

    def get_provider(self, provider_key: str) -> AIAdapter:
        adapter = self._providers.get(provider_key)
        if adapter is None:
            raise ValueError(f"Unsupported AI provider '{provider_key}'.")
        return adapter

    def validate_prompt(self, prompt: str) -> None:
        normalized = (prompt or "").strip()
        if not normalized:
            raise ValueError("Prompt is required.")
        for pattern in BLOCKED_PROMPT_PATTERNS:
            if pattern.search(normalized):
                raise ValueError("Prompt blocked by V3 safety policy.")

    def validate_grounding(self, grounding: Dict[str, Any]) -> None:
        items = grounding.get("items") or []
        if not items:
            raise ValueError("Grounding evidence is required for V3 AI sessions.")
        if len(items) > 25:
            raise ValueError("Grounding payload is too large for a reviewed V3 AI session.")

    def run(
        self,
        *,
        provider_key: str,
        capability: str,
        prompt: str,
        grounding: Dict[str, Any],
    ) -> Dict[str, Any]:
        if capability not in SUPPORTED_CAPABILITIES:
            raise ValueError(f"Unsupported AI capability '{capability}'.")
        self.validate_prompt(prompt)
        self.validate_grounding(grounding)
        adapter = self.get_provider(provider_key)
        if capability not in adapter.capabilities:
            raise ValueError(f"Provider '{provider_key}' does not support capability '{capability}'.")
        digest = hashlib.sha256(
            json.dumps({"prompt": prompt, "grounding": grounding}, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        result = adapter.run(capability=capability, prompt=prompt, grounding=grounding)
        return {
            "provider": adapter.catalog_entry(),
            "grounding_digest": digest,
            **result,
        }
