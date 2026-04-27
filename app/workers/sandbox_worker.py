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
import json
import logging
import multiprocessing as mp
import os
import signal
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


# ---------------------------------------------------------------------------
# Per-message handler
# ---------------------------------------------------------------------------


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

        lab_service = MalwareLabService(session)
        preflight_fn = getattr(lab_service, "enforce_run_execution_preflight", None)
        if callable(preflight_fn):
            preflight = preflight_fn(
                tenant,
                run=run,
                actor=str(message.get("actor") or "sandbox_worker"),
            )
            run.manifest = {**dict(run.manifest or {}), "detonation_preflight": preflight}
        result = lab_service.materialize_run_outputs(tenant, run=run)
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


# ---------------------------------------------------------------------------
# Single consumer loop
# ---------------------------------------------------------------------------


_SHUTDOWN = False


def _install_signal_handlers() -> None:
    def _request_shutdown(signum, _frame):  # pragma: no cover - signal-driven
        global _SHUTDOWN
        _SHUTDOWN = True
        logger.info("sandbox worker received signal %s; draining", signum)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _request_shutdown)
        except (ValueError, OSError):
            # Signals can only be registered from the main thread of the
            # main interpreter — multiprocessing workers fall back to
            # default handlers, which is fine.
            pass


def run_forever(*, max_messages: Optional[int] = None) -> None:
    logging.basicConfig(level=logging.INFO)
    _install_signal_handlers()

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

    logger.info("sandbox worker consuming %s group=%s consumer=%s", SANDBOX_WORK_STREAM, group, consumer)
    processed = 0
    while not _SHUTDOWN:
        rows = client.xreadgroup(group, consumer, {SANDBOX_WORK_STREAM: ">"}, block=5000, count=1)
        if not rows:
            time.sleep(0.05)
            continue
        for _, messages in rows:
            for entry_id, fields in messages:
                try:
                    process_sandbox_work(_decode_message(fields), bus=bus)
                except Exception:
                    logger.exception("leaving failed sandbox work message pending: %s", entry_id)
                    continue
                client.xack(SANDBOX_WORK_STREAM, group, entry_id)
                processed += 1
                if max_messages is not None and processed >= max_messages:
                    return


# ---------------------------------------------------------------------------
# Supervised process pool
# ---------------------------------------------------------------------------


def _child_entrypoint(child_index: int) -> None:  # pragma: no cover - subprocess
    """Entry point for forked workers under :func:`run_supervised`."""

    os.environ.setdefault("SHESHNAAG_SANDBOX_CONSUMER_NAME", f"sandbox-worker-{os.getpid()}-{child_index}")
    logging.basicConfig(level=logging.INFO)
    try:
        run_forever()
    except Exception:
        logger.exception("sandbox worker child crashed")
        # Non-zero exit triggers the supervisor to restart with backoff.
        raise SystemExit(1)


def run_supervised(*, concurrency: Optional[int] = None, max_restarts: int = 10) -> int:
    """Fork ``concurrency`` children, restart them on failure with backoff.

    Returns the exit code (``0`` on clean shutdown, ``1`` if any child kept
    crashing past ``max_restarts``).
    """

    logging.basicConfig(level=logging.INFO)
    if concurrency is None:
        concurrency = int(os.getenv("SHESHNAAG_SANDBOX_WORKER_CONCURRENCY", "2"))

    children: dict[int, mp.Process] = {}
    restart_counts: dict[int, int] = {idx: 0 for idx in range(concurrency)}
    last_restart: dict[int, float] = {idx: 0.0 for idx in range(concurrency)}

    def _start(idx: int) -> mp.Process:
        proc = mp.Process(target=_child_entrypoint, args=(idx,), name=f"sandbox-worker-{idx}", daemon=False)
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
                try:
                    proc.terminate()
                except Exception:
                    pass

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _shutdown)
        except (ValueError, OSError):
            pass

    exit_code = 0
    while not shutdown:
        time.sleep(1.0)
        for idx, proc in list(children.items()):
            if not proc.is_alive():
                exitcode = proc.exitcode
                logger.warning("sandbox supervisor child idx=%d exited code=%s", idx, exitcode)
                restart_counts[idx] += 1
                if restart_counts[idx] > max_restarts:
                    logger.error("sandbox supervisor child idx=%d exceeded max_restarts=%d; bailing", idx, max_restarts)
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


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="sandbox-worker")
    parser.add_argument("--supervised", action="store_true", help="Run as a supervised process pool")
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--max-restarts", type=int, default=10)
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    if args.supervised:
        return run_supervised(concurrency=args.concurrency, max_restarts=args.max_restarts)
    run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
