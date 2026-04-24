"""Live V4 run event stream APIs."""

from __future__ import annotations

import json

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from app.core.event_bus import EventBus, run_event_stream

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
def stream_run_events(run_id: int, last_id: str = "$"):
    bus = EventBus()
    stream = run_event_stream(run_id)

    def generate():
        yield ": connected\n\n"
        yield from (_sse(event) for event in bus.subscribe(stream, last_id=last_id))

    return StreamingResponse(generate(), media_type="text/event-stream")
