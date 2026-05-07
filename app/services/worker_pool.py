"""V5 W1b worker-pool control plane.

Two cooperating concerns live here:

  * :class:`WorkerCa` — a self-signed RSA-4096 certificate authority
    dedicated to the sandbox-worker fleet. Distinct from the cosign
    PKI used for artifact attestation: worker mTLS is intra-LAN trust;
    mixing it with the public artifact PKI complicates revocation
    (worker reimage shouldn't appear in Rekor) and forces every
    enrollment to make an outbound Fulcio call.

  * :class:`WorkerPoolService` — issues short-lived enrollment tokens,
    consumes them at bootstrap, signs the worker's CSR, persists the
    fleet registry, and accepts heartbeats / drain commands.

The CA private key is never stored in cleartext: ``WorkerCa`` derives
a KEK via HKDF from ``settings.secret_key`` (info=
``b"v5/worker-pool-ca/kek"``) and AES-GCM-encrypts the PEM-serialized
key before persisting. Loading the CA decrypts in-memory only. The
KEK derivation is *intentionally* domain-separated from any other use
of ``settings.secret_key`` so a leak of the JWT signing key does not
imply a leak of the CA key (and vice-versa) without the HKDF info string.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.time import utc_now
from app.models.worker_pool import (
    Worker,
    WorkerCaKey,
    WorkerEnrollmentToken,
)


_KEK_HKDF_INFO = b"v5/worker-pool-ca/kek"
_AES_GCM_KEY_LEN = 32  # 256-bit
_AES_GCM_NONCE_LEN = 12

# CA defaults.
_CA_KEY_BITS = 4096
_CA_VALIDITY = timedelta(days=365 * 10)  # 10 years
# Worker certs are short-lived (90 days) so V5 doesn't need CRL machinery.
_WORKER_CERT_VALIDITY = timedelta(days=90)

_ENROLLMENT_TOKEN_TTL = timedelta(minutes=15)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class WorkerCaError(RuntimeError):
    """Base class for worker-pool CA errors."""


class CaNotInitializedError(WorkerCaError):
    """The worker-pool CA has not been initialized yet."""


class EnrollmentTokenInvalidError(ValueError):
    """The presented enrollment token is unknown / consumed / expired."""


class WorkerNotFoundError(LookupError):
    """The named worker does not exist."""


# ---------------------------------------------------------------------------
# Data carriers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnrollmentToken:
    """A freshly minted single-use enrollment token.

    The plaintext value is returned to lab_lead exactly once; only the
    hash is persisted server-side.
    """

    token: str
    expires_at: datetime


@dataclass(frozen=True)
class BootstrapResult:
    """The control-plane response to a successful worker bootstrap."""

    worker_id: int
    worker_uuid: str
    cert_pem: str
    ca_pem: str
    redis_url: str
    not_after: datetime


# ---------------------------------------------------------------------------
# KEK derivation (domain-separated from JWT signing key)
# ---------------------------------------------------------------------------


def _derive_kek(secret_key: str) -> bytes:
    """Derive the worker-pool KEK from the application secret_key.

    HKDF-SHA256 with a fixed info string. A salt is *not* required here
    because secret_key has full entropy by deployment policy, and the
    domain-separation comes from the info string. Changing the info
    string is a backward-incompatible CA migration (V6+).
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_GCM_KEY_LEN,
        salt=None,
        info=_KEK_HKDF_INFO,
    ).derive(secret_key.encode("utf-8"))


# ---------------------------------------------------------------------------
# WorkerCa
# ---------------------------------------------------------------------------


class WorkerCa:
    """Self-signed CA for sandbox-worker fleet mTLS.

    Stateless wrapper over the persisted ``worker_ca_keys`` row. Loads
    the encrypted private key on first use; callers must hold a session.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # ----- lifecycle ------------------------------------------------------

    def initialize_if_missing(self, *, actor: str) -> WorkerCaKey:
        """Generate the CA on first run; idempotent."""
        existing = self._active_row()
        if existing is not None:
            return existing

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=_CA_KEY_BITS,
        )
        not_before = datetime.now(timezone.utc)
        not_after = not_before + _CA_VALIDITY
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Sheshnaag Worker Pool CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sheshnaag"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "worker-pool-ca"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        encrypted_pk, nonce = self._encrypt_private_key(private_key)

        row = WorkerCaKey(
            cert_pem=cert_pem,
            encrypted_private_key=encrypted_pk,
            nonce=nonce,
            not_before=not_before.replace(tzinfo=None),
            not_after=not_after.replace(tzinfo=None),
            is_active=True,
            created_by=actor,
        )
        self._session.add(row)
        self._session.flush()
        return row

    # ----- signing --------------------------------------------------------

    def sign_csr(self, csr_pem: str) -> tuple[str, datetime]:
        """Sign a worker CSR. Returns (cert_pem, not_after)."""
        row = self._active_row()
        if row is None:
            raise CaNotInitializedError("call initialize_if_missing first")

        ca_key = self._decrypt_private_key(row.encrypted_private_key, row.nonce)
        ca_cert = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        if not csr.is_signature_valid:
            raise ValueError("csr_signature_invalid")

        not_before = datetime.now(timezone.utc)
        not_after = not_before + _WORKER_CERT_VALIDITY
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return cert_pem, not_after

    def cert_pem(self) -> str:
        row = self._active_row()
        if row is None:
            raise CaNotInitializedError("ca not initialized")
        return row.cert_pem

    def cert_fingerprint(self, cert_pem: str) -> str:
        """SHA-256 hex fingerprint of an x509 cert (uppercase, no colons)."""
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        return cert.fingerprint(hashes.SHA256()).hex().upper()

    # ----- internals ------------------------------------------------------

    def _active_row(self) -> Optional[WorkerCaKey]:
        return (
            self._session.query(WorkerCaKey)
            .filter_by(is_active=True)
            .order_by(desc(WorkerCaKey.id))
            .first()
        )

    def _encrypt_private_key(
        self, private_key: rsa.RSAPrivateKey
    ) -> tuple[bytes, bytes]:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        kek = _derive_kek(settings.secret_key)
        nonce = os.urandom(_AES_GCM_NONCE_LEN)
        ciphertext = AESGCM(kek).encrypt(nonce, pem, associated_data=b"worker-pool-ca")
        return ciphertext, nonce

    def _decrypt_private_key(
        self, ciphertext: bytes, nonce: bytes
    ) -> rsa.RSAPrivateKey:
        kek = _derive_kek(settings.secret_key)
        pem = AESGCM(kek).decrypt(nonce, ciphertext, associated_data=b"worker-pool-ca")
        return serialization.load_pem_private_key(pem, password=None)


# ---------------------------------------------------------------------------
# Service: enrollment, heartbeat, drain
# ---------------------------------------------------------------------------


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class WorkerPoolService:
    """Worker registry + enrollment + heartbeat + drain."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # ----- enrollment tokens ---------------------------------------------

    def issue_enrollment_token(
        self, *, issued_by: str, ttl: timedelta = _ENROLLMENT_TOKEN_TTL
    ) -> EnrollmentToken:
        """Mint a single-use token. Plaintext returned exactly once."""
        plaintext = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + ttl
        row = WorkerEnrollmentToken(
            token_hash=_hash_token(plaintext),
            issued_by=issued_by,
            issued_at=datetime.now(timezone.utc).replace(tzinfo=None),
            expires_at=expires_at.replace(tzinfo=None),
        )
        self._session.add(row)
        self._session.flush()
        return EnrollmentToken(token=plaintext, expires_at=expires_at)

    def _consume_token(self, token: str) -> WorkerEnrollmentToken:
        row = (
            self._session.query(WorkerEnrollmentToken)
            .filter_by(token_hash=_hash_token(token))
            .first()
        )
        if row is None:
            raise EnrollmentTokenInvalidError("unknown_token")
        if row.consumed_at is not None:
            raise EnrollmentTokenInvalidError("token_already_consumed")
        now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
        if row.expires_at < now_naive:
            raise EnrollmentTokenInvalidError("token_expired")
        return row

    # ----- bootstrap ------------------------------------------------------

    def bootstrap(
        self,
        *,
        enrollment_token: str,
        csr_pem: str,
        capability_flags: List[str],
        redis_url: str,
        actor: str = "worker-bootstrap",
    ) -> BootstrapResult:
        """Validate token, sign CSR, register the worker."""
        token_row = self._consume_token(enrollment_token)

        ca = WorkerCa(self._session)
        ca.initialize_if_missing(actor=actor)
        cert_pem, not_after = ca.sign_csr(csr_pem)
        fingerprint = ca.cert_fingerprint(cert_pem)
        ca_pem = ca.cert_pem()

        worker_uuid = str(uuid.uuid4())
        worker = Worker(
            worker_uuid=worker_uuid,
            cert_fingerprint=fingerprint,
            cert_pem=cert_pem,
            capability_flags=list(capability_flags or []),
            state="online",
            last_heartbeat=datetime.now(timezone.utc).replace(tzinfo=None),
            enrolled_at=datetime.now(timezone.utc).replace(tzinfo=None),
            enrolled_by=token_row.issued_by,
        )
        self._session.add(worker)
        self._session.flush()

        token_row.consumed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        token_row.consumed_by_worker_id = worker.id
        self._session.flush()

        return BootstrapResult(
            worker_id=worker.id,
            worker_uuid=worker_uuid,
            cert_pem=cert_pem,
            ca_pem=ca_pem,
            redis_url=redis_url,
            not_after=not_after,
        )

    # ----- registry CRUD --------------------------------------------------

    def list_workers(self) -> List[Worker]:
        return self._session.query(Worker).order_by(Worker.id).all()

    def get_worker(self, worker_id: int) -> Worker:
        row = self._session.query(Worker).filter_by(id=worker_id).first()
        if row is None:
            raise WorkerNotFoundError(f"worker_id={worker_id}")
        return row

    def heartbeat(
        self,
        worker_id: int,
        *,
        capability_flags: Optional[List[str]] = None,
    ) -> Worker:
        worker = self.get_worker(worker_id)
        worker.last_heartbeat = datetime.now(timezone.utc).replace(tzinfo=None)
        if capability_flags is not None:
            worker.capability_flags = list(capability_flags)
        if worker.state == "offline":
            worker.state = "online"
        self._session.flush()
        return worker

    def drain(self, worker_id: int) -> Worker:
        worker = self.get_worker(worker_id)
        worker.state = "draining"
        self._session.flush()
        return worker

    def mark_offline(self, worker_id: int) -> Worker:
        worker = self.get_worker(worker_id)
        worker.state = "offline"
        self._session.flush()
        return worker

    # ----- artifact verification (used by control plane on return path) --

    def verify_artifact_signature(
        self,
        *,
        worker_id: int,
        body: bytes,
        signature: bytes,
    ) -> bool:
        """Verify a JWS-style detached signature against the worker's
        enrolled cert public key. Returns True iff the signature checks.

        V5 uses raw RSA-SHA256 signatures (PKCS#1 v1.5); the JWS header
        is implicit (alg=RS256) because the protocol is intra-LAN.
        Migrating to detached JWS proper is V6 polish.
        """
        from cryptography.hazmat.primitives.asymmetric import padding

        worker = self.get_worker(worker_id)
        cert = x509.load_pem_x509_certificate(worker.cert_pem.encode("utf-8"))
        public_key = cert.public_key()
        try:
            public_key.verify(
                signature,
                body,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False
