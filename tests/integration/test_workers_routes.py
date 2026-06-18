"""Integration tests for V5 worker pool routes."""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.api.routes.workers import router as workers_router
from app.core.config import settings
from app.core.database import Base, get_sync_session
from app.core.security import TokenData, verify_token


def _make_csr_pem() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "worker-int"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sheshnaag"),
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


@pytest.fixture(autouse=True)
def _auth_enabled(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)


@pytest.fixture()
def app_fixture():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    app = FastAPI()
    app.include_router(workers_router)

    def _override_session():
        s = Session()
        try:
            yield s
            s.commit()
        finally:
            s.close()

    app.dependency_overrides[get_sync_session] = _override_session
    yield app, Session
    engine.dispose()


def _client_as(app, roles):
    app.dependency_overrides[verify_token] = lambda: TokenData(username="lab_lead", roles=roles)
    return TestClient(app)


def test_bootstrap_requires_valid_enrollment_token(app_fixture):
    app, _ = app_fixture
    client = TestClient(app)
    r = client.post(
        "/api/v5/workers/bootstrap",
        json={
            "enrollment_token": "not-a-real-token",
            "csr_pem": _make_csr_pem(),
            "capability_flags": ["linux"],
        },
    )
    assert r.status_code == 403


def test_enrollment_bootstrap_heartbeat_drain_flow(app_fixture):
    app, _ = app_fixture
    client = _client_as(app, ["lab_lead"])

    issued = client.post("/api/v5/workers/enrollment-tokens")
    assert issued.status_code == 200
    token = issued.json()["token"]

    boot = client.post(
        "/api/v5/workers/bootstrap",
        json={
            "enrollment_token": token,
            "csr_pem": _make_csr_pem(),
            "capability_flags": ["linux", "kvm"],
        },
    )
    assert boot.status_code == 200
    body = boot.json()
    worker_id = body["worker_id"]
    assert body["cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert body["redis_url"].startswith("rediss://")

    listed = client.get("/api/v5/workers")
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    hb = client.post(
        f"/api/v5/workers/{worker_id}/heartbeat",
        json={"capability_flags": ["linux", "kvm", "pcap"]},
    )
    assert hb.status_code == 200
    assert hb.json()["state"] == "online"

    drained = client.post(f"/api/v5/workers/{worker_id}/drain")
    assert drained.status_code == 200
    assert drained.json()["state"] == "draining"


def test_issue_enrollment_token_requires_lab_lead(app_fixture):
    app, _ = app_fixture
    client = _client_as(app, ["analyst"])
    r = client.post("/api/v5/workers/enrollment-tokens")
    assert r.status_code == 403
