"""Sandbox worker consuming queued V4 run execution jobs."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Optional

import redis

from app.core.database import SessionLocal
from app.core.event_bus import EventBus, SANDBOX_WORK_STREAM, run_event_stream
from app.core.time import utc_now
from app.models.sheshnaag import LabRun, RunEvent
from app.models.v2 import Tenant
from app.services.malware_lab_service import MalwareLabService

logger = logging.getLogger(__name__)


def _event(run_id: int, event_type: str, *, severity: str = "info", source: str = "sandbox_worker", payload: Optional[dict] = None) -> dict:
    return {
        "run_id": run_id,
        "type": event_type,
        "timestamp": utc_now().isoformat(),
        "severity": severity,
        "source": source,
        "payload": payload or {},
    }


def _record_event(session, run_id: int, event_type: str, payload: dict, level: str = "info") -> None:
    session.add(
        RunEvent(
            run_id=run_id,
            event_type=event_type,
            level=level,
            message=payload.get("message") or event_type,
            payload=payload,
        )
    )


def process_sandbox_work(message: dict[str, Any], *, bus: Optional[EventBus] = None) -> dict[str, Any]:
    bus = bus or EventBus()
    run_id = int(message["run_id"])
    tenant_id = int(message["tenant_id"])
    session = SessionLocal()
    try:
        run = session.query(LabRun).filter(LabRun.id == run_id, LabRun.tenant_id == tenant_id).first()
        tenant = session.query(Tenant).filter(Tenant.id == tenant_id).first()
        if run is None or tenant is None:
            raise ValueError("run_or_tenant_not_found")

        run.state = "running"
        run.started_at = run.started_at or utc_now()
        started = _event(run_id, "run_started", payload={"correlation_id": message.get("correlation_id")})
        _record_event(session, run_id, "run_started", started)
        bus.publish(run_event_stream(run_id), started)
        session.commit()

        result = MalwareLabService(session).materialize_run_outputs(tenant, run=run)
        run.state = "completed"
        run.ended_at = utc_now()
        completed = _event(run_id, "run_completed", payload=result)
        _record_event(session, run_id, "run_completed", completed)
        bus.publish(run_event_stream(run_id), completed)
        session.commit()
        return {"run_id": run_id, "status": "completed", "result": result}
    except Exception as exc:
        session.rollback()
        run = session.query(LabRun).filter(LabRun.id == run_id, LabRun.tenant_id == tenant_id).first()
        if run is not None:
            run.state = "errored"
            run.ended_at = utc_now()
            failed = _event(run_id, "run_failed", severity="error", payload={"error": str(exc)})
            _record_event(session, run_id, "run_failed", failed, level="error")
            bus.publish(run_event_stream(run_id), failed)
            session.commit()
        logger.exception("Sandbox work failed for run_id=%s", run_id)
        raise
    finally:
        session.close()


def _decode_message(fields: dict) -> dict[str, Any]:
    raw = fields.get(b"data") or fields.get("data")
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    return json.loads(raw or "{}")


def run_forever() -> None:
    logging.basicConfig(level=logging.INFO)
    bus = EventBus()
    client = bus.client
    if client is None:
        raise RuntimeError("Redis is required for the sandbox worker")

    group = os.getenv("SHESHNAAG_SANDBOX_CONSUMER_GROUP", "sandbox-workers")
    consumer = os.getenv("SHESHNAAG_SANDBOX_CONSUMER_NAME", f"sandbox-worker-{os.getpid()}")
    try:
        client.xgroup_create(SANDBOX_WORK_STREAM, group, id="0-0", mkstream=True)
    except redis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise

    logger.info("Sandbox worker consuming %s group=%s consumer=%s", SANDBOX_WORK_STREAM, group, consumer)
    while True:
        rows = client.xreadgroup(group, consumer, {SANDBOX_WORK_STREAM: ">"}, block=5000, count=1)
        if not rows:
            time.sleep(0.1)
            continue
        for _, messages in rows:
            for entry_id, fields in messages:
                try:
                    process_sandbox_work(_decode_message(fields), bus=bus)
                except Exception:
                    logger.exception("Leaving failed sandbox work message pending: %s", entry_id)
                    continue
                client.xack(SANDBOX_WORK_STREAM, group, entry_id)


if __name__ == "__main__":
    run_forever()
