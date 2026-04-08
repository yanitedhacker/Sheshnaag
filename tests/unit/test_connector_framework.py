"""Unit tests for the FeedConnector abstraction and registry (WS1-T1)."""

import asyncio
from datetime import datetime
from typing import Optional

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.ingestion.connector import (
    ConnectorResult,
    FeedConnector,
    get_registered_connectors,
    register_connector,
)
from app.ingestion.feed_aggregator import FeedAggregator


def _make_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


class _StubConnector(FeedConnector):
    """In-memory stub used only for testing."""

    name = "__test_stub__"
    display_name = "Test Stub"
    category = "test"
    source_url = "https://example.com"
    supports_cursor = True

    def __init__(self):
        self.call_count = 0

    async def fetch(self, session, *, since=None, cursor=None, limit=2000):
        self.call_count += 1
        return ConnectorResult(
            source=self.name,
            items_fetched=3,
            items_new=2,
            items_updated=1,
            cursor="test-cursor-1",
        )


# ---- Registry tests --------------------------------------------------------

@pytest.mark.unit
def test_builtin_connectors_are_registered():
    registry = get_registered_connectors()
    assert "nvd" in registry
    assert "exploit_db" in registry


@pytest.mark.unit
def test_register_connector_decorator():
    @register_connector
    class _TempConnector(FeedConnector):
        name = "__temp_test__"
        display_name = "Temp"

        async def fetch(self, session, **kw):
            return ConnectorResult(source=self.name)

    assert get_registered_connectors().get("__temp_test__") is _TempConnector


@pytest.mark.unit
def test_register_connector_requires_name():
    with pytest.raises(ValueError, match="must define a 'name'"):

        @register_connector
        class _BadConnector(FeedConnector):
            name = ""

            async def fetch(self, session, **kw):
                return ConnectorResult(source="")


# ---- Aggregator invocation order -------------------------------------------

@pytest.mark.unit
def test_aggregator_iterates_all_connectors():
    stub1 = _StubConnector()
    stub1.__class__ = type("Stub1", (_StubConnector,), {"name": "__stub_a__"})
    stub1.name = "__stub_a__"
    stub2 = _StubConnector()
    stub2.__class__ = type("Stub2", (_StubConnector,), {"name": "__stub_b__"})
    stub2.name = "__stub_b__"

    session = _make_session()
    aggregator = FeedAggregator(session, connectors=[stub1, stub2])

    assert set(aggregator.connector_names) == {"__stub_a__", "__stub_b__"}


@pytest.mark.unit
def test_aggregator_sync_connector_uses_state():
    stub = _StubConnector()
    session = _make_session()
    aggregator = FeedAggregator(session, connectors=[stub])

    result = asyncio.get_event_loop().run_until_complete(
        aggregator.sync_connector("__test_stub__")
    )
    assert result.items_fetched == 3
    assert result.items_new == 2
    assert stub.call_count == 1


@pytest.mark.unit
def test_connector_result_to_dict():
    r = ConnectorResult(source="test", items_fetched=5, items_new=3, items_updated=2)
    d = r.to_dict()
    assert d["source"] == "test"
    assert d["items_fetched"] == 5
    assert d["items_new"] == 3


@pytest.mark.unit
def test_hash_payload_deterministic():
    payload = {"cve_id": "CVE-2024-1234", "score": 9.8}
    h1 = FeedConnector.hash_payload(payload)
    h2 = FeedConnector.hash_payload(payload)
    assert h1 == h2
    assert len(h1) == 64
