"""Queue-to-worker helper used by Docker-backed release smokes."""

from __future__ import annotations

from typing import Any, Callable, Dict

from app.core.config import settings
from app.core.event_bus import EventBus, SANDBOX_WORK_STREAM
from app.workers import sandbox_worker


def configure_in_memory_worker_queue() -> None:
    """Use the EventBus memory fallback for a deterministic one-process smoke."""

    settings.redis_url = "redis://127.0.0.1:1/15"


def process_queued_run(
    *,
    run: Dict[str, Any],
    session_factory: Callable[..., Any],
) -> Dict[str, Any]:
    """Consume one queued run and require the worker to complete it."""

    if run.get("state") != "queued":
        raise RuntimeError(
            "run did not enter the worker queue: "
            f"state={run.get('state')} transcript={run.get('run_transcript')}"
        )

    bus = EventBus()
    queued_message = next(
        bus.subscribe(
            SANDBOX_WORK_STREAM,
            last_id="0-0",
            block_ms=10,
        )
    )
    if int(queued_message.get("run_id", -1)) != int(run["id"]):
        raise RuntimeError(
            "sandbox queue returned the wrong run: "
            f"expected={run['id']} actual={queued_message.get('run_id')}"
        )

    sandbox_worker.SessionLocal = session_factory
    result = sandbox_worker.process_sandbox_work(queued_message, bus=bus)
    if result.get("status") != "completed":
        raise RuntimeError(f"sandbox worker did not complete the run: {result}")
    return result
