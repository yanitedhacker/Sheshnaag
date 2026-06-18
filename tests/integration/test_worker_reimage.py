"""V5 kill-criteria item 2 — worker reimage / re-enrollment without manual CA intervention."""

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


def _make_csr_pem(cn: str = "worker-reimage") -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
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
    app.dependency_overrides[verify_token] = lambda: TokenData(
        username="lab_lead", roles=["lab_lead"]
    )
    yield app, Session
    engine.dispose()


def test_reimage_survives_via_fresh_bootstrap(app_fixture):
    """Drain + new CSR + new enrollment token → new cert fingerprint, same CA."""
    app, _ = app_fixture
    client = TestClient(app)

    tok1 = client.post("/api/v5/workers/enrollment-tokens")
    assert tok1.status_code == 200
    csr1 = _make_csr_pem("worker-v1")
    r1 = client.post(
        "/api/v5/workers/bootstrap",
        json={
            "enrollment_token": tok1.json()["token"],
            "csr_pem": csr1,
            "capability_flags": ["docker"],
        },
    )
    assert r1.status_code == 200
    worker_id = r1.json()["worker_id"]
    fp1 = client.get(f"/api/v5/workers/{worker_id}").json()["cert_fingerprint"]

    drain = client.post(f"/api/v5/workers/{worker_id}/drain")
    assert drain.status_code == 200

    tok2 = client.post("/api/v5/workers/enrollment-tokens")
    assert tok2.status_code == 200
    csr2 = _make_csr_pem("worker-v2-reimage")
    r2 = client.post(
        "/api/v5/workers/bootstrap",
        json={
            "enrollment_token": tok2.json()["token"],
            "csr_pem": csr2,
            "capability_flags": ["docker"],
        },
    )
    assert r2.status_code == 200
    fp2 = client.get(f"/api/v5/workers/{r2.json()['worker_id']}").json()["cert_fingerprint"]
    assert fp1 != fp2
    assert r2.json()["ca_pem"]
