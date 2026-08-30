"""Sandbox worker consuming queued V4 run execution jobs.

The worker has two modes:

- ``run_forever()`` — single consumer loop, used by `python -m
  app.workers.sandbox_worker` when the orchestrator runs one process per
  container. Suitable for compose deployments where the container manager
  owns parallelism.
- ``run_supervised()`` — process-pool supervisor that forks N children,
  restarts them on crash with exponential backoff, and propagates
  ``SIGTERM``/``SIGINT`` to the pool. Used in production by
  ``python -m app.workers.sandbox_worker --supervised``.

Both modes share the same per-message handler (``process_sandbox_work``),
which runs end-to-end: it materialises the run via
:class:`MalwareLabService`, publishes lifecycle events to the run stream,
and acks Redis Streams entries on success. Failures stay pending so a
peer consumer can retake the message; we surface a ``run_failed`` event
to the SSE stream so the analyst sees the error in real time.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import multiprocessing as mp
import os
import signal
import time
from collections.abc import Collection
from typing import Any

import redis
from sqlalchemy import text

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.event_bus import EventBus, run_event_stream
from app.core.time import utc_now
from app.lab.execution_requirements import required_worker_capabilities_for_run
from app.models.sheshnaag import EvidenceArtifact, LabRun, RunEvent
from app.models.v2 import Tenant
from app.services.malware_lab_service import MalwareLabService
from app.services.sheshnaag_service import SheshnaagService
from app.workers.routing import (
    SANDBOX_CONSUMER_GROUP,
    WorkEntryLease,
    WorkerRoutingError,
    WorkerRunClaimUnavailable,
    assert_message_matches_persisted_requirements,
    assert_worker_can_process,
    claim_stale_work_rows,
    ensure_consumer_groups,
    normalize_capabilities,
    streams_for_worker,
)

logger = logging.getLogger(__name__)


def check_worker_dependencies() -> bool:
    """Return true only when the worker can reach Redis and the database."""

    redis_client = None
    session = None
    try:
        redis_client = redis.from_url(
            settings.redis_url,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        if redis_client.ping() is not True:
            return False
        session = SessionLocal()
        session.execute(text("SELECT 1"))
        return True
    except Exception:
        logger.warning("sandbox worker dependency health check failed")
        return False
    finally:
        for resource in (session, redis_client):
            if resource is None:
                continue
            with contextlib.suppress(Exception):
                resource.close()


# ---------------------------------------------------------------------------
# Per-message handler
# ---------------------------------------------------------------------------


def _event(
    run_id: int,
    event_type: str,
    *,
    severity: str = "info",
    source: str = "sandbox_worker",
    payload: dict | None = None,
) -> dict:
    return {
        "run_id": run_id,
        "type": event_type,
        "timestamp": utc_now().isoformat(),
        "severity": severity,
        "source": source,
        "payload": payload or {},
    }


def _record_event(
    session, run_id: int, event_type: str, payload: dict, level: str = "info"
) -> None:
    session.add(
        RunEvent(
            run_id=run_id,
            event_type=event_type,
            level=level,
            message=payload.get("message") or event_type,
            payload=payload,
        )
    )


def configured_worker_capabilities() -> frozenset[str]:
    """Return the explicit capability set for this worker process."""

    raw = os.getenv("SHESHNAAG_WORKER_CAPABILITIES", "docker")
    return normalize_capabilities(raw.split(","))


def _select_run_for_execution(session, *, run_id: int, tenant_id: int):
    """Claim one run row without waiting behind another active worker."""

    return (
        session.query(LabRun)
        .filter(LabRun.id == run_id, LabRun.tenant_id == tenant_id)
        .with_for_update(skip_locked=True)
        .first()
    )


def process_sandbox_work(
    message: dict[str, Any],
    *,
    bus: EventBus | None = None,
    worker_capabilities: Collection[str] | None = None,
) -> dict[str, Any]:
    capabilities = (
        configured_worker_capabilities()
        if worker_capabilities is None
        else normalize_capabilities(worker_capabilities)
    )
    assert_worker_can_process(message, capabilities)
    bus = bus or EventBus()
    run_id = int(message["run_id"])
    tenant_id = int(message["tenant_id"])
    session = SessionLocal()
    try:
        run = _select_run_for_execution(
            session,
            run_id=run_id,
            tenant_id=tenant_id,
        )
        tenant = session.query(Tenant).filter(Tenant.id == tenant_id).first()
        if run is None:
            raise WorkerRunClaimUnavailable("run_claim_unavailable")
        if tenant is None:
            raise ValueError("run_or_tenant_not_found")

        persisted_requirements = required_worker_capabilities_for_run(run)
        assert_message_matches_persisted_requirements(
            message,
            persisted_requirements,
            capabilities,
        )

        if run.state == "completed":
            evidence_rows = (
                session.query(EvidenceArtifact)
                .filter(EvidenceArtifact.run_id == run.id)
                .all()
            )
            worker_execution = dict((run.manifest or {}).get("worker_execution") or {})
            live_evidence_count = sum(
                1
                for item in evidence_rows
                if str(
                    (item.payload or {}).get("collection_state")
                    or ((item.payload or {}).get("collector_health") or {}).get("status")
                    or ""
                ).lower()
                in {"live", "ok"}
            )
            return {
                "run_id": run_id,
                "status": "completed",
                "result": {
                    "state": "completed",
                    "evidence_count": len(evidence_rows),
                    "live_evidence_count": live_evidence_count,
                    "cleanup_state": worker_execution.get("cleanup_state"),
                },
            }

        run.started_at = run.started_at or utc_now()
        started = _event(
            run_id, "run_started", payload={"correlation_id": message.get("correlation_id")}
        )
        _record_event(session, run_id, "run_started", started)
        bus.publish(run_event_stream(run_id), started)
        session.flush()

        preflight_fn = getattr(
            MalwareLabService(session),
            "enforce_run_execution_preflight",
            None,
        )
        if callable(preflight_fn):
            preflight = preflight_fn(
                tenant,
                run=run,
                actor=str(message.get("actor") or "sandbox_worker"),
            )
            run.manifest = {**dict(run.manifest or {}), "detonation_preflight": preflight}
        result = SheshnaagService(session).execute_queued_run(
            tenant,
            run_id=run_id,
            actor=str(message.get("actor") or "sandbox_worker"),
        )
        if result.get("state") != "completed" or int(result.get("evidence_count") or 0) < 1:
            raise RuntimeError(f"worker_execution_incomplete:{result}")
        completed = _event(run_id, "run_completed", payload=result)
        _record_event(session, run_id, "run_completed", completed)
        bus.publish(run_event_stream(run_id), completed)
        session.commit()
        return {"run_id": run_id, "status": "completed", "result": result}
    except WorkerRoutingError:
        session.rollback()
        logger.warning("Rejected sandbox routing contract for run_id=%s", run_id)
        raise
    except Exception as exc:
        session.rollback()
        run = (
            session.query(LabRun).filter(LabRun.id == run_id, LabRun.tenant_id == tenant_id).first()
        )
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


# ---------------------------------------------------------------------------
# Single consumer loop
# ---------------------------------------------------------------------------


_SHUTDOWN = False
_WORK_READ_BLOCK_MS = 1000


def _install_signal_handlers() -> None:
    def _request_shutdown(signum, _frame):  # pragma: no cover - signal-driven
        global _SHUTDOWN
        _SHUTDOWN = True
        logger.info("sandbox worker received signal %s; draining", signum)

    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(ValueError, OSError):
            signal.signal(sig, _request_shutdown)
            # Signals can only be registered from the main thread of the
            # main interpreter — multiprocessing workers fall back to
            # default handlers, which is fine.


def _read_work_rows(client, *, group: str, consumer: str, streams: dict[str, str]) -> list:
    """Read one queue item without crashing when an idle poll times out."""

    try:
        return client.xreadgroup(
            group,
            consumer,
            streams,
            block=_WORK_READ_BLOCK_MS,
            count=1,
        )
    except redis.exceptions.TimeoutError:
        logger.warning("Redis work-stream read timed out; retrying")
        return []


def run_forever(*, max_messages: int | None = None) -> None:
    logging.basicConfig(level=logging.INFO)
    _install_signal_handlers()

    bus = EventBus()
    client = bus.client
    if client is None:
        raise RuntimeError("Redis is required for the sandbox worker")

    capabilities = configured_worker_capabilities()
    streams = streams_for_worker(capabilities)
    if not streams:
        raise RuntimeError("Worker has no complete capability set for any work stream")

    group = SANDBOX_CONSUMER_GROUP
    consumer = os.getenv("SHESHNAAG_SANDBOX_CONSUMER_NAME", f"sandbox-worker-{os.getpid()}")
    ensure_consumer_groups(client, streams)

    logger.info(
        "sandbox worker consuming %s group=%s consumer=%s",
        sorted(streams),
        group,
        consumer,
    )
    processed = 0
    while not _SHUTDOWN:
        rows = _read_work_rows(client, group=group, consumer=consumer, streams=streams)
        if not rows:
            rows = claim_stale_work_rows(client, streams, consumer=consumer)
            if not rows:
                time.sleep(0.05)
                continue
        for stream_name, messages in rows:
            if isinstance(stream_name, bytes):
                stream_name = stream_name.decode("utf-8")
            for entry_id, fields in messages:
                try:
                    with WorkEntryLease(
                        client,
                        stream=stream_name,
                        consumer=consumer,
                        entry_id=entry_id,
                    ):
                        process_sandbox_work(
                            _decode_message(fields),
                            bus=bus,
                            worker_capabilities=capabilities,
                        )
                except Exception:
                    logger.exception("leaving failed sandbox work message pending: %s", entry_id)
                    continue
                client.xack(stream_name, group, entry_id)
                processed += 1
                if max_messages is not None and processed >= max_messages:
                    return


# ---------------------------------------------------------------------------
# Supervised process pool
# ---------------------------------------------------------------------------


def _child_entrypoint(child_index: int) -> None:  # pragma: no cover - subprocess
    """Entry point for forked workers under :func:`run_supervised`."""

    os.environ.setdefault(
        "SHESHNAAG_SANDBOX_CONSUMER_NAME", f"sandbox-worker-{os.getpid()}-{child_index}"
    )
    logging.basicConfig(level=logging.INFO)
    try:
        run_forever()
    except Exception as exc:
        logger.exception("sandbox worker child crashed")
        # Non-zero exit triggers the supervisor to restart with backoff.
        raise SystemExit(1) from exc


def run_supervised(*, concurrency: int | None = None, max_restarts: int = 10) -> int:
    """Fork ``concurrency`` children, restart them on failure with backoff.

    Returns the exit code (``0`` on clean shutdown, ``1`` if any child kept
    crashing past ``max_restarts``).
    """

    logging.basicConfig(level=logging.INFO)
    if concurrency is None:
        concurrency = int(os.getenv("SHESHNAAG_SANDBOX_WORKER_CONCURRENCY", "2"))

    children: dict[int, mp.Process] = {}
    restart_counts: dict[int, int] = dict.fromkeys(range(concurrency), 0)
    last_restart: dict[int, float] = dict.fromkeys(range(concurrency), 0.0)

    def _start(idx: int) -> mp.Process:
        proc = mp.Process(
            target=_child_entrypoint, args=(idx,), name=f"sandbox-worker-{idx}", daemon=False
        )
        proc.start()
        children[idx] = proc
        last_restart[idx] = time.time()
        logger.info("sandbox supervisor started child idx=%d pid=%s", idx, proc.pid)
        return proc

    for idx in range(concurrency):
        _start(idx)

    shutdown = False

    def _shutdown(signum, _frame):
        nonlocal shutdown
        shutdown = True
        logger.info("sandbox supervisor received signal %s; forwarding to children", signum)
        for proc in children.values():
            if proc.is_alive():
                with contextlib.suppress(Exception):
                    proc.terminate()

    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(ValueError, OSError):
            signal.signal(sig, _shutdown)

    exit_code = 0
    while not shutdown:
        time.sleep(1.0)
        for idx, proc in list(children.items()):
            if not proc.is_alive():
                exitcode = proc.exitcode
                logger.warning("sandbox supervisor child idx=%d exited code=%s", idx, exitcode)
                restart_counts[idx] += 1
                if restart_counts[idx] > max_restarts:
                    logger.error(
                        "sandbox supervisor child idx=%d exceeded max_restarts=%d; bailing",
                        idx,
                        max_restarts,
                    )
                    exit_code = 1
                    shutdown = True
                    break
                # Exponential backoff capped at 30s.
                delay = min(30.0, 1.5 ** restart_counts[idx])
                logger.info("sandbox supervisor restarting child idx=%d in %.1fs", idx, delay)
                time.sleep(delay)
                _start(idx)

    # Drain.
    for proc in children.values():
        if proc.is_alive():
            proc.terminate()
        proc.join(timeout=15)
        if proc.is_alive():
            proc.kill()
            proc.join()
    return exit_code


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="sandbox-worker")
    parser.add_argument(
        "--supervised", action="store_true", help="Run as a supervised process pool"
    )
    parser.add_argument(
        "--healthcheck",
        action="store_true",
        help="Check worker Redis and database dependencies, then exit",
    )
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--max-restarts", type=int, default=10)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.healthcheck:
        return 0 if check_worker_dependencies() else 1
    if args.supervised:
        return run_supervised(concurrency=args.concurrency, max_restarts=args.max_restarts)
    run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
