"""V5 W1b worker-pool unit tests — CA signing, enrollment, heartbeat, drain."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  registers tables
from app.core.database import Base
from app.services.worker_pool import (
    EnrollmentTokenInvalidError,
    WorkerCa,
    WorkerNotFoundError,
    WorkerPoolService,
)


def _session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return Session()


def _make_csr_pem() -> tuple[str, rsa.RSAPrivateKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "worker-test"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sheshnaag"),
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return csr_pem, private_key


@pytest.mark.unit
def test_worker_ca_signs_csr_and_verifies_against_ca():
    session = _session()
    ca = WorkerCa(session)
    ca.initialize_if_missing(actor="lab_lead@test")
    session.commit()

    csr_pem, _ = _make_csr_pem()
    cert_pem, not_after = ca.sign_csr(csr_pem)
    session.commit()

    worker_cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem().encode("utf-8"))
    assert worker_cert.issuer == ca_cert.subject
    assert not_after > datetime.now(UTC)


@pytest.mark.unit
def test_enrollment_token_single_use_and_bootstrap_registers_worker():
    session = _session()
    svc = WorkerPoolService(session)
    issued = svc.issue_enrollment_token(issued_by="lab_lead@test")
    session.commit()

    csr_pem, _ = _make_csr_pem()
    result = svc.bootstrap(
        enrollment_token=issued.token,
        csr_pem=csr_pem,
        capability_flags=["linux", "kvm"],
        redis_url="redis://127.0.0.1:6379/0",
        actor="worker-bootstrap",
    )
    session.commit()

    assert result.worker_id > 0
    assert result.cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert result.ca_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert result.redis_url.startswith("redis://")

    workers = svc.list_workers()
    assert len(workers) == 1
    assert workers[0].capability_flags == ["linux", "kvm"]
    assert workers[0].state == "online"

    with pytest.raises(EnrollmentTokenInvalidError, match="token_already_consumed"):
        svc.bootstrap(
            enrollment_token=issued.token,
            csr_pem=csr_pem,
            capability_flags=[],
            redis_url="redis://127.0.0.1:6379/0",
        )


@pytest.mark.unit
def test_expired_enrollment_token_rejected():
    session = _session()
    svc = WorkerPoolService(session)
    issued = svc.issue_enrollment_token(issued_by="lab_lead@test", ttl=timedelta(seconds=-1))
    session.commit()

    csr_pem, _ = _make_csr_pem()
    with pytest.raises(EnrollmentTokenInvalidError, match="token_expired"):
        svc.bootstrap(
            enrollment_token=issued.token,
            csr_pem=csr_pem,
            capability_flags=[],
            redis_url="redis://127.0.0.1:6379/0",
        )


@pytest.mark.unit
def test_heartbeat_updates_timestamp_and_drain_flips_state():
    session = _session()
    svc = WorkerPoolService(session)
    issued = svc.issue_enrollment_token(issued_by="lab_lead@test")
    csr_pem, _ = _make_csr_pem()
    boot = svc.bootstrap(
        enrollment_token=issued.token,
        csr_pem=csr_pem,
        capability_flags=["linux"],
        redis_url="redis://127.0.0.1:6379/0",
    )
    session.commit()

    before = svc.get_worker(boot.worker_id).last_heartbeat
    worker = svc.heartbeat(boot.worker_id, capability_flags=["linux", "pcap"])
    session.commit()
    assert worker.last_heartbeat is not None
    assert worker.capability_flags == ["linux", "pcap"]
    if before is not None:
        assert worker.last_heartbeat >= before

    drained = svc.drain(boot.worker_id)
    session.commit()
    assert drained.state == "draining"


@pytest.mark.unit
def test_verify_artifact_signature_uses_enrolled_worker_cert():
    session = _session()
    svc = WorkerPoolService(session)
    issued = svc.issue_enrollment_token(issued_by="lab_lead@test")
    csr_pem, private_key = _make_csr_pem()
    boot = svc.bootstrap(
        enrollment_token=issued.token,
        csr_pem=csr_pem,
        capability_flags=["linux"],
        redis_url="redis://127.0.0.1:6379/0",
    )
    session.commit()

    body = b'{"run_id": 42, "status": "completed"}'
    signature = private_key.sign(body, padding.PKCS1v15(), hashes.SHA256())
    assert svc.verify_artifact_signature(
        worker_id=boot.worker_id,
        body=body,
        signature=signature,
    )

    assert not svc.verify_artifact_signature(
        worker_id=boot.worker_id,
        body=body,
        signature=b"not-a-real-signature",
    )


@pytest.mark.unit
def test_get_worker_missing_raises():
    session = _session()
    svc = WorkerPoolService(session)
    with pytest.raises(WorkerNotFoundError):
        svc.get_worker(999)
