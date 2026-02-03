"""
Pytest configuration and shared fixtures.

Integration tests require a running Docker environment.
Run with: pytest -m integration (requires docker-compose up)
Run unit tests only: pytest -m unit
"""

import os
import time

import httpx
import pytest


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers",
        "integration: marks tests as integration tests (require running services)"
    )
    config.addinivalue_line(
        "markers",
        "unit: marks tests as unit tests (no external dependencies)"
    )


def pytest_collection_modifyitems(config, items):
    """
    Automatically skip integration tests when services are not available.

    This allows running `pytest` without -m flag and still having
    integration tests skip gracefully when Docker services aren't running.
    """
    # Check if we should skip integration tests
    skip_integration = not os.getenv("RUN_INTEGRATION_TESTS", "").lower() in ("1", "true", "yes")

    if skip_integration:
        skip_marker = pytest.mark.skip(
            reason="Integration tests skipped. Set RUN_INTEGRATION_TESTS=1 or use -m 'not integration'"
        )
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_marker)


@pytest.fixture(scope="session")
def lab_api_base() -> str:
    """
    Base URL for the integration lab API.

    In docker-compose network this should be http://api:8000.
    For local testing, set LAB_API_BASE=http://localhost:8000
    """
    return os.getenv("LAB_API_BASE", "http://localhost:8000").rstrip("/")


@pytest.fixture(scope="session")
def lab_httpx_client(lab_api_base: str) -> httpx.Client:
    """HTTP client for integration tests."""
    return httpx.Client(base_url=lab_api_base, timeout=20.0)


@pytest.fixture(scope="session")
def wait_for_lab_api(lab_httpx_client: httpx.Client):
    """
    Wait for /health endpoint to respond.

    This fixture ensures the API is ready before running integration tests.
    """
    deadline = time.time() + float(os.getenv("LAB_WAIT_TIMEOUT_SECONDS", "30"))
    last_err = None

    while time.time() < deadline:
        try:
            r = lab_httpx_client.get("/health")
            if r.status_code == 200:
                return
        except Exception as e:
            last_err = e
        time.sleep(1)

    raise RuntimeError(
        f"Lab API did not become healthy in time. "
        f"Make sure the API is running at {lab_httpx_client.base_url}. "
        f"Last error: {last_err}"
    )
