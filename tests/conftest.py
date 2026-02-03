import os
import time

import httpx
import pytest


@pytest.fixture(scope="session")
def lab_api_base() -> str:
    """
    Base URL for the integration lab API.

    In docker-compose network this should be http://api:8000.
    """
    return os.getenv("LAB_API_BASE", "http://api:8000").rstrip("/")


@pytest.fixture(scope="session")
def lab_httpx_client(lab_api_base: str) -> httpx.Client:
    return httpx.Client(base_url=lab_api_base, timeout=20.0)


@pytest.fixture(scope="session")
def wait_for_lab_api(lab_httpx_client: httpx.Client):
    """
    Wait for /health to respond.
    """
    deadline = time.time() + float(os.getenv("LAB_WAIT_TIMEOUT_SECONDS", "60"))
    last_err = None
    while time.time() < deadline:
        try:
            r = lab_httpx_client.get("/health")
            if r.status_code == 200:
                return
        except Exception as e:
            last_err = e
        time.sleep(1)
    raise RuntimeError(f"Lab API did not become healthy in time. Last error: {last_err}")

