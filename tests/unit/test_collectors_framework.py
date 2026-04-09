"""Collector registry and recipe-driven resolution."""

import pytest

from app.lab.collector_contract import (
    DEFAULT_RECIPE_COLLECTORS,
    build_provider_result_dict,
    recipe_collector_names,
)
from app.lab.collectors.osquery_snapshot import OsquerySnapshotCollector
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
