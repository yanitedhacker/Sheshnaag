"""V4 operational health APIs."""

from __future__ import annotations

import os
import shutil

import redis
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_sync_session

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


@router.get("/health")
def ops_health(session: Session = Depends(get_sync_session)):
    try:
        session.execute(text("SELECT 1"))
        db = "ok"
    except Exception:
        db = "missing"

    return {
        "api": "ok",
        "db": db,
        "redis": _redis_status(),
        "lab_deps": {
            "nft": _binary_status("nft"),
            "dnsmasq": _binary_status("dnsmasq"),
            "inetsim": _binary_status("inetsim"),
            "virsh": _binary_status("virsh"),
            "limactl": _binary_status("limactl"),
            "vol": _binary_status("vol"),
            "zeek": _binary_status("zeek"),
            "tetragon": _binary_status("tetragon"),
        },
        "ai_providers": {
            "anthropic": _provider_status("ANTHROPIC_API_KEY"),
            "openai": _provider_status("OPENAI_API_KEY"),
            "gemini": _provider_status("GEMINI_API_KEY", "GOOGLE_API_KEY"),
            "azure_openai": _provider_status("AZURE_OPENAI_API_KEY"),
            "bedrock": _provider_status("AWS_ACCESS_KEY_ID", "AWS_PROFILE"),
            "local": "configured",
        },
    }
