"""Collector registry and recipe-driven resolution."""

import pytest

from app.lab.collector_contract import (
    DEFAULT_RECIPE_COLLECTORS,
    build_provider_result_dict,
    recipe_collector_names,
)
from app.lab.collectors import instantiate_collectors
from app.lab.collectors.registry import COLLECTOR_REGISTRY


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


@pytest.mark.unit
def test_registry_covers_known_recipe_collectors():
    for name in DEFAULT_RECIPE_COLLECTORS:
        assert name in COLLECTOR_REGISTRY
