"""Capability-aware Redis routing for queued sandbox work."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

from app.services.sheshnaag_service import SheshnaagService


def _requirements_module():
    try:
        return importlib.import_module("app.lab.execution_requirements")
    except ModuleNotFoundError:
        pytest.fail("app.lab.execution_requirements is required for worker routing")


def _routing_module():
    try:
        return importlib.import_module("app.workers.routing")
    except ModuleNotFoundError:
        pytest.fail("app.workers.routing is required for worker routing")


def test_standard_execute_job_requires_docker_worker():
    requirements = _requirements_module()

    required = requirements.required_worker_capabilities(
        provider="docker_kali",
        launch_mode="execute",
        analysis_mode="cve_validation",
    )

    assert required == frozenset({"docker"})


def test_libvirt_detonation_requires_linux_kvm_and_telemetry():
    requirements = _requirements_module()

    required = requirements.required_worker_capabilities(
        provider="libvirt",
        launch_mode="execute",
        analysis_mode="malware_detonation",
    )

    assert required == frozenset(
        {"linux", "kvm", "libvirt", "pcap", "zeek", "secure-mode"}
    )


def test_lima_detonation_requires_lima_and_telemetry():
    requirements = _requirements_module()

    required = requirements.required_worker_capabilities(
        provider="lima",
        launch_mode="execute",
        analysis_mode="email_analysis",
    )

    assert required == frozenset({"lima", "pcap", "zeek", "secure-mode"})


def test_non_execute_run_needs_no_worker():
    requirements = _requirements_module()

    required = requirements.required_worker_capabilities(
        provider="libvirt",
        launch_mode="simulated",
        analysis_mode="malware_detonation",
    )

    assert required == frozenset()


def test_routing_uses_versioned_streams_and_one_consumer_group():
    routing = _routing_module()

    assert routing.SANDBOX_STANDARD_WORK_STREAM == "sheshnaag:sandbox:work:standard"
    assert routing.SANDBOX_LIBVIRT_WORK_STREAM == (
        "sheshnaag:sandbox:work:detonation:libvirt"
    )
    assert routing.SANDBOX_LIMA_WORK_STREAM == "sheshnaag:sandbox:work:detonation:lima"
    assert routing.SANDBOX_CONSUMER_GROUP == "sheshnaag:sandbox:workers:v1"
    assert routing.ROUTING_VERSION == 1


def test_worker_subscribes_only_to_compatible_streams():
    routing = _routing_module()

    assert routing.streams_for_worker({"docker"}) == {
        "sheshnaag:sandbox:work:standard": ">"
    }
    assert routing.streams_for_worker(
        {"linux", "kvm", "libvirt", "pcap", "zeek", "secure-mode"}
    ) == {"sheshnaag:sandbox:work:detonation:libvirt": ">"}
    assert routing.streams_for_worker(
        {"lima", "pcap", "zeek", "secure-mode"}
    ) == {"sheshnaag:sandbox:work:detonation:lima": ">"}
    assert routing.streams_for_worker(
        {"docker", "linux", "kvm", "libvirt", "pcap", "zeek", "secure-mode"}
    ) == {
        "sheshnaag:sandbox:work:standard": ">",
        "sheshnaag:sandbox:work:detonation:libvirt": ">",
    }


def test_incompatible_worker_is_rejected_with_missing_capabilities():
    routing = _routing_module()
    message = {
        "routing_version": 1,
        "required_capabilities": [
            "kvm",
            "libvirt",
            "linux",
            "pcap",
            "secure-mode",
            "zeek",
        ],
    }

    with pytest.raises(routing.WorkerCapabilityMismatch) as excinfo:
        routing.assert_worker_can_process(message, {"docker"})

    assert excinfo.value.missing == frozenset(
        {"kvm", "libvirt", "linux", "pcap", "secure-mode", "zeek"}
    )


def test_compatible_worker_accepts_current_routing_version():
    routing = _routing_module()
    capabilities = {"linux", "kvm", "libvirt", "pcap", "zeek", "secure-mode"}
    message = {
        "routing_version": 1,
        "required_capabilities": sorted(capabilities),
    }

    routing.assert_worker_can_process(message, capabilities)


def test_control_plane_enqueues_risky_run_on_provider_stream(monkeypatch):
    routing = _routing_module()
    published: list[tuple[str, dict]] = []

    class FakeBus:
        def publish(self, stream, event):
            published.append((stream, event))
            return "17-0"

    event_bus = importlib.import_module("app.core.event_bus")
    monkeypatch.setattr(event_bus, "EventBus", FakeBus)
    service = object.__new__(SheshnaagService)
    run = SimpleNamespace(
        id=71,
        provider="libvirt",
        launch_mode="execute",
        manifest={"v3_context": {"analysis_mode": "malware_detonation"}},
    )
    tenant = SimpleNamespace(id=9)

    entry_id = service._enqueue_sandbox_work(run=run, tenant=tenant, actor="analyst")

    assert entry_id == "17-0"
    assert published == [
        (
            routing.SANDBOX_LIBVIRT_WORK_STREAM,
            {
                "run_id": 71,
                "tenant_id": 9,
                "actor": "analyst",
                "correlation_id": published[0][1]["correlation_id"],
                "required_capabilities": [
                    "kvm",
                    "libvirt",
                    "linux",
                    "pcap",
                    "secure-mode",
                    "zeek",
                ],
                "routing_version": 1,
            },
        )
    ]


def test_stream_selection_keeps_secure_providers_separate():
    routing = _routing_module()

    assert routing.stream_for_requirements(
        {"linux", "kvm", "libvirt", "pcap", "zeek", "secure-mode"}
    ) == routing.SANDBOX_LIBVIRT_WORK_STREAM
    assert routing.stream_for_requirements(
        {"lima", "pcap", "zeek", "secure-mode"}
    ) == routing.SANDBOX_LIMA_WORK_STREAM


def test_consumer_groups_use_one_contract_and_keep_preexisting_jobs():
    routing = _routing_module()
    calls = []

    class FakeClient:
        def xgroup_create(self, stream, group, *, id, mkstream):
            calls.append((stream, group, id, mkstream))

    routing.ensure_consumer_groups(
        FakeClient(),
        {routing.SANDBOX_STANDARD_WORK_STREAM: ">"},
    )

    assert calls == [
        (
            routing.SANDBOX_STANDARD_WORK_STREAM,
            routing.SANDBOX_CONSUMER_GROUP,
            "0-0",
            True,
        )
    ]


def test_consumer_group_creation_ignores_only_busygroup():
    routing = _routing_module()

    class DuplicateClient:
        def xgroup_create(self, *_args, **_kwargs):
            raise routing.redis.ResponseError("BUSYGROUP Consumer Group name already exists")

    routing.ensure_consumer_groups(
        DuplicateClient(),
        {routing.SANDBOX_STANDARD_WORK_STREAM: ">"},
    )

    class BrokenClient:
        def xgroup_create(self, *_args, **_kwargs):
            raise routing.redis.ResponseError("NOPERM user lacks permission")

    with pytest.raises(routing.redis.ResponseError, match="NOPERM"):
        routing.ensure_consumer_groups(
            BrokenClient(),
            {routing.SANDBOX_STANDARD_WORK_STREAM: ">"},
        )


def test_stale_pending_work_is_reclaimed_from_each_eligible_stream():
    routing = _routing_module()
    calls = []

    class FakeClient:
        def xautoclaim(self, stream, group, consumer, idle_ms, start_id, *, count):
            calls.append((stream, group, consumer, idle_ms, start_id, count))
            return [b"0-0", [(b"19-0", {b"data": b"{}"})], []]

    rows = routing.claim_stale_work_rows(
        FakeClient(),
        {routing.SANDBOX_STANDARD_WORK_STREAM: ">"},
        consumer="worker-7",
        min_idle_ms=45_000,
    )

    assert rows == [
        (
            routing.SANDBOX_STANDARD_WORK_STREAM,
            [(b"19-0", {b"data": b"{}"})],
        )
    ]
    assert calls == [
        (
            routing.SANDBOX_STANDARD_WORK_STREAM,
            routing.SANDBOX_CONSUMER_GROUP,
            "worker-7",
            45_000,
            "0-0",
            1,
        )
    ]
