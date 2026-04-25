"""Collector registry and recipe-driven resolution."""

import pytest

from app.lab.collector_contract import (
    DEFAULT_RECIPE_COLLECTORS,
    build_provider_result_dict,
    recipe_collector_names,
)
import app.lab.collectors.file_diff as file_diff_module
import app.lab.collectors.network_metadata as network_module
import app.lab.collectors.process_tree as process_module
from app.lab.collectors.file_diff import FileDiffCollector
from app.lab.collectors.network_metadata import NetworkMetadataCollector
from app.lab.collectors.pcap import PcapCollector
from app.lab.collectors.process_tree import ProcessTreeCollector
from app.lab.collectors.osquery_snapshot import OsquerySnapshotCollector
import app.lab.collectors.tracee_collector as tracee_module
from app.lab.collectors.tracee_collector import TraceeEventsCollector
from app.lab.collectors import instantiate_collectors
from app.lab.collectors.registry import COLLECTOR_REGISTRY
from app.lab.docker_kali_provider import DEFAULT_KALI_IMAGE, DockerKaliProvider


@pytest.mark.unit
def test_recipe_collector_names_defaults_when_missing():
    assert recipe_collector_names({}) == list(DEFAULT_RECIPE_COLLECTORS)


@pytest.mark.unit
def test_recipe_collector_names_subset_order():
    names = recipe_collector_names({"collectors": ["network_metadata", "process_tree"]})
    assert names == ["network_metadata", "process_tree"]


@pytest.mark.unit
def test_instantiate_collectors_dedupes():
    cols = instantiate_collectors(["process_tree", "process_tree", "file_diff"])
    assert [c.collector_name for c in cols] == ["process_tree", "file_diff"]


@pytest.mark.unit
def test_unknown_collector_falls_back_to_synthetic():
    cols = instantiate_collectors(["totally_unknown_collector"])
    assert len(cols) == 1
    ev = cols[0].collect(
        run_context={"run_id": 1, "launch_mode": "simulated"},
        provider_result=build_provider_result_dict(provider_run_ref="x", plan={"image": "test"}),
    )
    assert ev[0]["artifact_kind"] == "totally_unknown_collector"
    assert ev[0]["payload"].get("mode") == "synthetic"
    assert ev[0]["payload"].get("collection_state") == "skipped"


@pytest.mark.unit
def test_osquery_collector_reports_unavailable_without_osquery_image():
    collector = OsquerySnapshotCollector()
    evidence = collector.collect(
        run_context={"run_id": 1, "launch_mode": "execute"},
        provider_result=build_provider_result_dict(
            provider_run_ref="run-1",
            plan={"tooling_profile": {"profile": "baseline", "osquery_available": False}},
            state="running",
            container_id="container-123",
        ),
    )
    assert evidence[0]["payload"]["collection_state"] == "unavailable"
    assert evidence[0]["payload"]["reason"] == "image_not_osquery_capable"


@pytest.mark.unit
def test_provider_marks_osquery_capability_unavailable_on_baseline_image():
    provider = DockerKaliProvider()
    plan = provider.build_plan(
        revision_content={
            "base_image": DEFAULT_KALI_IMAGE,
            "collectors": ["process_tree", "osquery_snapshot"],
        },
        run_context={"tenant_slug": "demo", "analyst_name": "Tester", "run_id": 1},
    )
    capability = next(item for item in plan["collector_capabilities"] if item["collector_name"] == "osquery_snapshot")
    assert capability["status"] == "unavailable"


@pytest.mark.unit
def test_registry_covers_known_recipe_collectors():
    for name in DEFAULT_RECIPE_COLLECTORS:
        assert name in COLLECTOR_REGISTRY


@pytest.mark.unit
def test_provider_marks_tracee_capability_ready_on_tracee_profile():
    provider = DockerKaliProvider()
    plan = provider.build_plan(
        revision_content={
            "image_profile": "tracee_capable",
            "collectors": ["process_tree", "tracee_events"],
        },
        run_context={"tenant_slug": "demo", "analyst_name": "Tester", "run_id": 1},
    )
    capability = next(item for item in plan["collector_capabilities"] if item["collector_name"] == "tracee_events")
    assert capability["status"] == "ready"
    assert capability["tier"] == "supported"


@pytest.mark.unit
def test_tracee_collector_reports_supported_image_requirement():
    collector = TraceeEventsCollector()
    evidence = collector.collect(
        run_context={"run_id": 1, "launch_mode": "execute"},
        provider_result=build_provider_result_dict(
            provider_run_ref="run-1",
            plan={"tooling_profile": {"profile": "baseline", "tracee_available": False}},
            state="running",
            container_id="container-123",
        ),
    )
    assert evidence[0]["payload"]["collection_state"] == "skipped"
    assert "Tracee-capable" in evidence[0]["summary"]


@pytest.mark.unit
def test_tracee_live_payload_uses_standardized_session_fields(monkeypatch):
    collector = TraceeEventsCollector()

    def fake_run_in_guest(provider_result, argv, timeout_sec=90, stdin_text=None):
        joined = " ".join(argv)
        if "tracee version" in joined:
            return 0, "tracee version 1.0.0", ""
        return 0, '{"processName":"sh","eventName":"execve","argsNum":1}\n', ""

    monkeypatch.setattr(tracee_module, "run_in_guest", fake_run_in_guest)
    evidence = collector.collect(
        run_context={"run_id": 1, "launch_mode": "execute"},
        provider_result=build_provider_result_dict(
            provider_run_ref="run-1",
            plan={"provider": "docker_kali", "tooling_profile": {"profile": "tracee_capable", "tracee_available": True}},
            state="running",
            container_id="container-123",
        ),
    )
    payload = evidence[0]["payload"]
    assert payload["mode"] == "live"
    assert payload["session"]["transport"] == "docker_exec"
    assert payload["session"]["event_limit"] >= 1
    assert payload["support"]["supported"] is True


@pytest.mark.unit
def test_baseline_collectors_run_through_lima_guest_transport(monkeypatch):
    monkeypatch.setattr("app.lab.collectors.runtime.shutil.which", lambda name: f"/usr/bin/{name}")

    calls = []

    def fake_process_guest(provider_result, argv, timeout_sec=90, stdin_text=None):
        calls.append(("process_tree", argv))
        return 0, "1 0 /sbin/init\n42 1 bash -lc secure-smoke\n", ""

    def fake_file_guest(provider_result, argv, timeout_sec=90, stdin_text=None):
        calls.append(("file_diff", argv))
        return 0, "/workspace/secure-smoke.txt\n", ""

    def fake_network_guest(provider_result, argv, timeout_sec=90, stdin_text=None):
        calls.append(("network_metadata", argv))
        return 0, "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n", ""

    monkeypatch.setattr(process_module, "run_in_guest", fake_process_guest)
    monkeypatch.setattr(file_diff_module, "run_in_guest", fake_file_guest)
    monkeypatch.setattr(network_module, "run_in_guest", fake_network_guest)

    provider_result = build_provider_result_dict(
        provider_run_ref="lima-1",
        plan={"provider": "lima", "instance_name": "sheshnaag-lima-1"},
        state="running",
    )
    run_context = {"run_id": 1, "launch_mode": "execute"}

    process_payload = ProcessTreeCollector().collect(run_context=run_context, provider_result=provider_result)[0]["payload"]
    file_payload = FileDiffCollector().collect(run_context=run_context, provider_result=provider_result)[0]["payload"]
    network_payload = NetworkMetadataCollector().collect(run_context=run_context, provider_result=provider_result)[0]["payload"]

    assert process_payload["mode"] == "live"
    assert process_payload["transport"] == "lima_shell"
    assert file_payload["transport"] == "lima_shell"
    assert network_payload["transport"] == "lima_shell"
    assert {name for name, _ in calls} == {"process_tree", "file_diff", "network_metadata"}


@pytest.mark.unit
def test_baseline_collectors_keep_docker_guest_transport(monkeypatch):
    monkeypatch.setattr("app.lab.collectors.runtime.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(process_module, "run_in_guest", lambda *args, **kwargs: (0, "1 0 /sbin/init\n", ""))

    provider_result = build_provider_result_dict(
        provider_run_ref="docker-1",
        plan={"provider": "docker_kali"},
        state="running",
        container_id="container-123",
    )
    evidence = ProcessTreeCollector().collect(
        run_context={"run_id": 1, "launch_mode": "execute"},
        provider_result=provider_result,
    )

    assert evidence[0]["payload"]["mode"] == "live"
    assert evidence[0]["payload"]["transport"] == "docker_exec"


@pytest.mark.unit
def test_pcap_payload_marks_sensitive_bounded_capture(monkeypatch):
    collector = PcapCollector()

    def fake_run_in_guest(provider_result, argv, timeout_sec=90, stdin_text=None):
        return 0, "c2hlc2huYWFnLXBjYXAtcHJldmlldw==", ""

    import app.lab.collectors.pcap as pcap_module

    monkeypatch.setattr(pcap_module, "run_in_guest", fake_run_in_guest)
    monkeypatch.setattr(pcap_module, "env_flag_enabled", lambda name, default=False: True)

    evidence = collector.collect(
        run_context={"run_id": 1, "launch_mode": "execute"},
        provider_result=build_provider_result_dict(
            provider_run_ref="lima-1",
            plan={"provider": "lima", "instance_name": "sheshnaag-lima-1"},
            state="running",
        ),
    )
    payload = evidence[0]["payload"]
    assert payload["mode"] == "live"
    assert payload["capture_policy"]["bounded_capture"] is True
    assert payload["review_sensitivity"]["external_export_requires_confirmation"] is True
    assert payload["storage"]["contains_raw_payload"] is True
