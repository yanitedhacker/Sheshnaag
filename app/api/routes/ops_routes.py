"""V4 operational health APIs."""

from __future__ import annotations

import os
import platform
import shutil

import redis
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_sync_session
from app.core.object_store import get_object_store

router = APIRouter(prefix="/api/v4/ops", tags=["Sheshnaag V4 Ops"])


def _binary_status(binary: str) -> str:
    return "ok" if shutil.which(binary) else "missing"


def _redis_status() -> str:
    try:
        client = redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1)
        client.ping()
        return "ok"
    except Exception:
        return "missing"


def _provider_status(*names: str) -> str:
    return "configured" if any(os.getenv(name) for name in names) else "unconfigured"


def _truthy(value: str | None) -> bool:
    return bool(value) and value.strip().lower() in {"1", "true", "yes", "on"}


def _beta_health_required() -> bool:
    profile = (settings.deployment_profile or "").strip().lower()
    return _truthy(os.getenv("SHESHNAAG_REQUIRE_BETA_HEALTH")) or profile in {
        "design_partner_beta",
        "full_v4_beta",
        "release_verification",
    }


def _audit_signer_status() -> dict:
    choice = os.getenv("SHESHNAAG_AUDIT_SIGNER", "hmac").strip().lower()
    if choice == "cosign":
        try:
            import sigstore  # noqa: F401  # pragma: no cover - optional
            return {"backend": "cosign", "status": "configured"}
        except Exception:
            return {"backend": "cosign", "status": "missing_sigstore"}
    return {"backend": "hmac", "status": "dev_only"}


def _pgvector_status(session: Session) -> str:
    if "postgresql" not in settings.database_url.lower():
        return "dev_only"
    try:
        installed = session.execute(
            text("SELECT 1 FROM pg_extension WHERE extname = 'vector'")
        ).first()
        return "ok" if installed else "missing"
    except Exception:
        return "missing"


def _worker_queue_status() -> str:
    try:
        client = redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1)
        client.xinfo_stream("sheshnaag:sandbox:work")
        return "ok"
    except redis.exceptions.ResponseError as exc:
        return "empty" if "no such key" in str(exc).lower() else "missing"
    except Exception:
        return "missing"


def _otel_status() -> str:
    if not os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return "unconfigured"
    try:
        import opentelemetry  # noqa: F401  # pragma: no cover - optional
        return "configured"
    except Exception:
        return "missing_sdk"


def _object_store_status() -> dict:
    try:
        return get_object_store().health()
    except Exception as exc:  # pragma: no cover - defensive
        return {"status": "missing", "error": str(exc)}


def _kvm_status() -> str:
    if platform.system() != "Linux":
        return "unsupported_os"
    if os.path.exists("/dev/kvm"):
        return "ok"
    return "missing"


def _runtime_flag_status(name: str) -> str:
    return "on" if _truthy(os.getenv(name)) else "off"


@router.get("/health")
def ops_health(response: Response, session: Session = Depends(get_sync_session)):
    try:
        session.execute(text("SELECT 1"))
        db = "ok"
    except Exception:
        db = "missing"

    audit_signer = _audit_signer_status()
    object_store = _object_store_status()
    telemetry = {
        "otel": _otel_status(),
        "log_json": "on" if os.getenv("LOG_JSON", "").lower() in {"1", "true", "yes"} or settings.environment != "development" else "off",
    }
    lab_deps = {
        "nft": _binary_status("nft"),
        "dnsmasq": _binary_status("dnsmasq"),
        "inetsim": _binary_status("inetsim"),
        "virsh": _binary_status("virsh"),
        "limactl": _binary_status("limactl"),
        "vol": _binary_status("vol"),
        "zeek": _binary_status("zeek"),
        "tetragon": _binary_status("tetragon"),
        "kvm": _kvm_status(),
    }
    detonation_runtime = {
        "egress_enforce": _runtime_flag_status("SHESHNAAG_EGRESS_ENFORCE"),
        "pcap": _runtime_flag_status("SHESHNAAG_ENABLE_PCAP"),
        "require_memory_dump": _runtime_flag_status("SHESHNAAG_REQUIRE_MEMORY_DUMP"),
    }
    ai_providers = {
        "anthropic": _provider_status("ANTHROPIC_API_KEY"),
        "openai": _provider_status("OPENAI_API_KEY"),
        "gemini": _provider_status("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        "azure_openai": _provider_status("AZURE_OPENAI_API_KEY"),
        "bedrock": _provider_status("AWS_ACCESS_KEY_ID", "AWS_PROFILE"),
        "local": "configured",
    }
    body = {
        "api": "ok",
        "db": db,
        "redis": _redis_status(),
        "pgvector": _pgvector_status(session),
        "worker_queue": _worker_queue_status(),
        "object_store": object_store,
        "audit_signer": audit_signer,
        "telemetry": telemetry,
        "lab_deps": lab_deps,
        "detonation_runtime": detonation_runtime,
        "ai_providers": ai_providers,
    }

    blockers: list[str] = []
    if _beta_health_required():
        if body["db"] != "ok":
            blockers.append("db")
        if body["redis"] != "ok":
            blockers.append("redis")
        if body["pgvector"] != "ok":
            blockers.append("pgvector")
        if body["worker_queue"] == "missing":
            blockers.append("worker_queue")
        if object_store.get("status") != "ok" or object_store.get("backend") != "minio":
            blockers.append("object_store_minio")
        if audit_signer.get("backend") != "cosign" or audit_signer.get("status") != "configured":
            blockers.append("audit_signer_cosign")
        if telemetry["otel"] != "configured":
            blockers.append("otel")
        if detonation_runtime["egress_enforce"] != "on":
            blockers.append("detonation_runtime.egress_enforce")
        if detonation_runtime["pcap"] != "on":
            blockers.append("detonation_runtime.pcap")
        required_lab = {"nft", "dnsmasq", "virsh", "zeek", "kvm"}
        if detonation_runtime["require_memory_dump"] == "on":
            required_lab.add("vol")
        blockers.extend(f"lab_deps.{name}" for name in sorted(required_lab) if lab_deps.get(name) != "ok")
        for provider, provider_status in ai_providers.items():
            if provider_status != "configured":
                blockers.append(f"ai_providers.{provider}")

    body["beta"] = {
        "required": _beta_health_required(),
        "status": "ok" if not blockers else "blocked",
        "blockers": blockers,
    }
    if blockers:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return body
