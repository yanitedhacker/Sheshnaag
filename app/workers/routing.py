"""Redis stream selection and worker-side capability enforcement."""

from __future__ import annotations

import logging
import threading
from collections.abc import Collection, Mapping
from typing import Any

import redis

from app.lab.execution_requirements import (
    LIBVIRT_DETONATION_CAPABILITIES,
    LIMA_DETONATION_CAPABILITIES,
    STANDARD_WORKER_CAPABILITIES,
    normalize_capabilities,
)

ROUTING_VERSION = 1
SANDBOX_CONSUMER_GROUP = "sheshnaag:sandbox:workers:v1"
SANDBOX_STANDARD_WORK_STREAM = "sheshnaag:sandbox:work:standard"
SANDBOX_LIBVIRT_WORK_STREAM = "sheshnaag:sandbox:work:detonation:libvirt"
SANDBOX_LIMA_WORK_STREAM = "sheshnaag:sandbox:work:detonation:lima"
WORK_ENTRY_LEASE_REFRESH_SECONDS = 20.0

logger = logging.getLogger(__name__)


class WorkerRoutingError(RuntimeError):
    """Base error for a job that cannot be accepted by a worker."""


class WorkerRoutingVersionMismatch(WorkerRoutingError):
    """The queue entry uses a routing contract this worker does not support."""


class WorkerCapabilityMismatch(WorkerRoutingError):
    """The worker does not have every capability required by the job."""

    def __init__(self, missing: Collection[str]):
        self.missing = normalize_capabilities(missing)
        super().__init__(f"worker_missing_capabilities:{','.join(sorted(self.missing))}")


class WorkerRequirementMismatch(WorkerRoutingError):
    """The queue claim does not match the saved run contract."""


class WorkerRunClaimUnavailable(WorkerRoutingError):
    """The run does not exist or another worker holds its database claim."""


def stream_for_requirements(required: Collection[str]) -> str:
    """Select the versioned Redis stream for a derived requirement set."""

    normalized = normalize_capabilities(required)
    if "libvirt" in normalized:
        return SANDBOX_LIBVIRT_WORK_STREAM
    if "lima" in normalized:
        return SANDBOX_LIMA_WORK_STREAM
    return SANDBOX_STANDARD_WORK_STREAM


def streams_for_worker(capabilities: Collection[str]) -> dict[str, str]:
    """Return only streams that this worker class can safely consume."""

    held = normalize_capabilities(capabilities)
    streams: dict[str, str] = {}
    if STANDARD_WORKER_CAPABILITIES.issubset(held):
        streams[SANDBOX_STANDARD_WORK_STREAM] = ">"
    if LIBVIRT_DETONATION_CAPABILITIES.issubset(held):
        streams[SANDBOX_LIBVIRT_WORK_STREAM] = ">"
    if LIMA_DETONATION_CAPABILITIES.issubset(held):
        streams[SANDBOX_LIMA_WORK_STREAM] = ">"
    return streams


def ensure_consumer_groups(client, streams: Mapping[str, str]) -> None:
    """Create the canonical group without skipping entries already in a stream."""

    for stream in streams:
        try:
            client.xgroup_create(
                stream,
                SANDBOX_CONSUMER_GROUP,
                id="0-0",
                mkstream=True,
            )
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise


def claim_stale_work_rows(
    client,
    streams: Mapping[str, str],
    *,
    consumer: str,
    min_idle_ms: int = 90_000,
) -> list[tuple[str, list]]:
    """Claim one stale pending entry from each eligible stream."""

    rows: list[tuple[str, list]] = []
    for stream in streams:
        response = client.xautoclaim(
            stream,
            SANDBOX_CONSUMER_GROUP,
            consumer,
            min_idle_ms,
            "0-0",
            count=1,
        )
        messages = response[1] if len(response) > 1 else []
        if messages:
            rows.append((stream, messages))
    return rows


def refresh_work_entry_lease(
    client,
    *,
    stream: str,
    consumer: str,
    entry_id: str | bytes,
) -> None:
    """Reset the pending-entry idle timer for the active worker."""

    claimed = client.xclaim(
        stream,
        SANDBOX_CONSUMER_GROUP,
        consumer,
        0,
        [entry_id],
        justid=True,
    )
    if not claimed:
        raise WorkerRoutingError("work_entry_lease_lost")


class WorkEntryLease:
    """Refresh a Redis pending-entry lease until work exits."""

    def __init__(
        self,
        client,
        *,
        stream: str,
        consumer: str,
        entry_id: str | bytes,
        refresh_seconds: float = WORK_ENTRY_LEASE_REFRESH_SECONDS,
    ) -> None:
        self.client = client
        self.stream = stream
        self.consumer = consumer
        self.entry_id = entry_id
        self.refresh_seconds = max(1.0, float(refresh_seconds))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> WorkEntryLease:
        refresh_work_entry_lease(
            self.client,
            stream=self.stream,
            consumer=self.consumer,
            entry_id=self.entry_id,
        )
        self._thread = threading.Thread(
            target=self._refresh_loop,
            name="sandbox-work-lease",
            daemon=True,
        )
        self._thread.start()
        return self

    def _refresh_loop(self) -> None:
        while not self._stop.wait(self.refresh_seconds):
            try:
                refresh_work_entry_lease(
                    self.client,
                    stream=self.stream,
                    consumer=self.consumer,
                    entry_id=self.entry_id,
                )
            except Exception:
                logger.exception("sandbox work-entry lease refresh failed")

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def assert_worker_can_process(
    message: Mapping[str, Any],
    capabilities: Collection[str],
) -> None:
    """Reject an unsupported routing version or missing worker capability."""

    if message.get("routing_version") != ROUTING_VERSION:
        raise WorkerRoutingVersionMismatch(
            f"unsupported_routing_version:{message.get('routing_version')}"
        )

    raw_required = message.get("required_capabilities")
    if not isinstance(raw_required, list) or not raw_required:
        raise WorkerRoutingError("required_capabilities_missing")

    required = normalize_capabilities(raw_required)
    missing = required - normalize_capabilities(capabilities)
    if missing:
        raise WorkerCapabilityMismatch(missing)


def assert_message_matches_persisted_requirements(
    message: Mapping[str, Any],
    expected: Collection[str],
    capabilities: Collection[str],
) -> None:
    """Require the queue claim to equal the server-owned saved contract."""

    assert_worker_can_process(message, capabilities)
    raw_required = message.get("required_capabilities")
    queued = normalize_capabilities(raw_required if isinstance(raw_required, list) else [])
    persisted = normalize_capabilities(expected)
    if queued != persisted:
        raise WorkerRequirementMismatch(
            "queue_requirement_mismatch:"
            f"queued={','.join(sorted(queued))};"
            f"persisted={','.join(sorted(persisted))}"
        )
