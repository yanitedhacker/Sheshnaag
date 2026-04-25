"""Live V4 run event stream APIs."""

from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.event_bus import EventBus, run_event_stream
from app.core.security import TokenData, verify_token
from app.core.tenancy import resolve_tenant
from app.models.sheshnaag import LabRun

router = APIRouter(prefix="/api/v4/runs", tags=["Sheshnaag V4 Live Runs"])


def _sse(event: dict) -> str:
    event_id = event.get("id")
    lines = []
    if event_id:
        lines.append(f"id: {event_id}")
    lines.append("event: run_event")
    lines.append(f"data: {json.dumps(event, default=str)}")
    return "\n".join(lines) + "\n\n"


@router.get("/{run_id}/events")
def stream_run_events(
    run_id: int,
    last_id: str = "$",
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — auth gate
):
    # Anti-enumeration: require explicit tenant context and verify the run
    # belongs to it. Without this an attacker could subscribe to any
    # consecutively-numbered run id and receive cross-tenant event data.
    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=False
    )
    run = (
        session.query(LabRun)
        .filter(LabRun.id == run_id, LabRun.tenant_id == tenant.id)
        .first()
    )
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    bus = EventBus()
    stream = run_event_stream(run_id)

    def generate():
        yield ": connected\n\n"
        yield from (_sse(event) for event in bus.subscribe(stream, last_id=last_id))

    return StreamingResponse(generate(), media_type="text/event-stream")
