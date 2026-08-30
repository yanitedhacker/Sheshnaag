"""V5 W1b sandbox-worker agent.

A long-running daemon that:

  1. On first boot, generates an RSA-3072 private key + CSR and POSTs
     them to the control plane along with an enrollment token.
  2. Receives a signed cert + CA bundle + Redis URL from the control
     plane.
  3. Connects to ``rediss://`` Redis with the cert as its mTLS client
     identity.
  4. Pulls jobs from the existing sandbox-work consumer group, calls
     :func:`app.workers.sandbox_worker.process_sandbox_work` (unchanged
     from V4), wraps the result in an RSA-PKCS1v15-SHA256 signature
     using its private key, and ``xadd``-s to the per-run return
     stream.
  5. Heartbeats every 30 s; voluntarily exits when the heartbeat
     response says ``state=draining``.

This daemon does NOT replace ``sandbox_worker.py`` — it composes with
it. Operators run ``python -m app.workers.sandbox_agent`` on each
worker host; the agent dispatches each pulled job through the same
``process_sandbox_work`` handler.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from app.core.event_bus import (
    build_tls_redis_client,
    sandbox_return_stream,
)
from app.workers.routing import (
    SANDBOX_CONSUMER_GROUP,
    WorkEntryLease,
    claim_stale_work_rows,
    ensure_consumer_groups,
    normalize_capabilities,
    streams_for_worker,
)

logger = logging.getLogger(__name__)


_DEFAULT_KEY_DIR = Path("/var/lib/sheshnaag-worker")
_KEY_FILE = "key.pem"
_CSR_FILE = "csr.pem"
_CERT_FILE = "cert.pem"
_CA_FILE = "ca.pem"
_STATE_FILE = "state.json"

_HEARTBEAT_INTERVAL_SECONDS = 30
@dataclass
class AgentState:
    """Runtime state read from / written to ``state.json``."""

    worker_id: int
    worker_uuid: str
    redis_url: str

    @classmethod
    def load(cls, state_path: Path) -> AgentState:
        with state_path.open("r") as f:
            data = json.load(f)
        return cls(**data)

    def save(self, state_path: Path) -> None:
        state_path.write_text(json.dumps(self.__dict__))


# ---------------------------------------------------------------------------
# Bootstrap (key + CSR + enrollment)
# ---------------------------------------------------------------------------


def _generate_keypair_and_csr(
    key_dir: Path, hostname: str, lan_ip: str | None
) -> tuple[rsa.RSAPrivateKey, str, str]:
    """Idempotent: re-generate only if key.pem doesn't exist.

    Returns (private_key, csr_pem, worker_uuid_subject).
    """
    key_dir.mkdir(parents=True, exist_ok=True)
    key_path = key_dir / _KEY_FILE
    csr_path = key_dir / _CSR_FILE

    if key_path.exists():
        with key_path.open("rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Write 0600.
        old_umask = os.umask(0o077)
        try:
            with key_path.open("wb") as f:
                f.write(key_pem)
            os.chmod(key_path, 0o600)
        finally:
            os.umask(old_umask)

    # Build CSR. Subject CN includes a generated UUID-ish marker so the
    # cert subject is non-empty even before the control plane assigns a
    # worker_uuid; the control plane authoritatively assigns its own
    # ID at bootstrap.
    import uuid as _uuid

    cn_marker = f"worker-{_uuid.uuid4()}"
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn_marker),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sheshnaag"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sandbox-worker"),
        ]
    )
    sans = [x509.DNSName(hostname)]
    if lan_ip:
        from ipaddress import ip_address

        try:
            sans.append(x509.IPAddress(ip_address(lan_ip)))
        except ValueError:
            logger.warning("invalid lan_ip %r, skipping IP SAN", lan_ip)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    csr_path.write_text(csr_pem)
    return private_key, csr_pem, cn_marker


def _bootstrap(
    *,
    control_plane_url: str,
    enrollment_token: str,
    capability_flags: list[str],
    key_dir: Path,
    hostname: str,
    lan_ip: str | None,
) -> AgentState:
    """One-shot: generate key + CSR, POST to control plane, store result."""
    _, csr_pem, _ = _generate_keypair_and_csr(key_dir, hostname, lan_ip)

    response = requests.post(
        f"{control_plane_url.rstrip('/')}/api/v5/workers/bootstrap",
        json={
            "enrollment_token": enrollment_token,
            "csr_pem": csr_pem,
            "capability_flags": capability_flags,
        },
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()

    (key_dir / _CERT_FILE).write_text(data["cert_pem"])
    (key_dir / _CA_FILE).write_text(data["ca_pem"])

    state = AgentState(
        worker_id=int(data["worker_id"]),
        worker_uuid=data["worker_uuid"],
        redis_url=data["redis_url"],
    )
    state.save(key_dir / _STATE_FILE)
    logger.info(
        "worker enrolled: id=%s uuid=%s",
        state.worker_id,
        state.worker_uuid,
    )
    return state


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


class HeartbeatLoop:
    """Sends periodic heartbeats; tracks drain signal."""

    def __init__(
        self,
        *,
        control_plane_url: str,
        worker_id: int,
        capability_flags: list[str],
    ) -> None:
        self._url = f"{control_plane_url.rstrip('/')}/api/v5/workers/{worker_id}/heartbeat"
        self._capability_flags = capability_flags
        self._draining = False
        self._stop = False

    @property
    def draining(self) -> bool:
        return self._draining

    @property
    def stopped(self) -> bool:
        return self._stop

    def signal_stop(self) -> None:
        self._stop = True

    def tick(self) -> None:
        try:
            r = requests.post(
                self._url,
                json={"capability_flags": self._capability_flags},
                timeout=10,
            )
            if r.status_code == 200:
                payload = r.json()
                if payload.get("state") == "draining":
                    self._draining = True
                    logger.info("control plane signaled drain")
        except Exception as exc:  # pragma: no cover - infra
            logger.warning("heartbeat failed: %s", exc)


# ---------------------------------------------------------------------------
# Signed-artifact return
# ---------------------------------------------------------------------------


def _sign_payload(private_key: rsa.RSAPrivateKey, body: bytes) -> bytes:
    """RSA-PKCS1v15-SHA256 signature over the canonical payload bytes."""
    return private_key.sign(body, padding.PKCS1v15(), hashes.SHA256())


def _publish_return(
    redis_client,
    *,
    run_id: int,
    payload: dict,
    signature: bytes,
) -> None:
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    redis_client.xadd(
        sandbox_return_stream(run_id),
        {
            "data": body,
            "signature": signature.hex(),
        },
    )


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def run_agent(
    *,
    control_plane_url: str,
    enrollment_token: str | None,
    capability_flags: list[str],
    key_dir: Path = _DEFAULT_KEY_DIR,
    hostname: str | None = None,
    lan_ip: str | None = None,
    consumer_name: str | None = None,
) -> int:
    """Start the agent. Returns process exit code.

    Bootstrap is automatic when ``state.json`` is missing — caller must
    supply ``enrollment_token`` in that case. Subsequent restarts reuse
    the persisted key + cert.
    """

    state_path = key_dir / _STATE_FILE
    hostname = hostname or socket.getfqdn()
    normalized_capabilities = normalize_capabilities(capability_flags)
    streams = streams_for_worker(normalized_capabilities)
    if not streams:
        logger.error("worker has no complete capability set for any work stream")
        return 3

    if not state_path.exists():
        if not enrollment_token:
            logger.error("no state.json and no enrollment token; cannot bootstrap")
            return 2
        state = _bootstrap(
            control_plane_url=control_plane_url,
            enrollment_token=enrollment_token,
            capability_flags=capability_flags,
            key_dir=key_dir,
            hostname=hostname,
            lan_ip=lan_ip,
        )
    else:
        state = AgentState.load(state_path)

    # Load private key for signing return payloads.
    with (key_dir / _KEY_FILE).open("rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    redis_client = build_tls_redis_client(
        state.redis_url,
        ssl_certfile=str(key_dir / _CERT_FILE),
        ssl_keyfile=str(key_dir / _KEY_FILE),
        ssl_ca_certs=str(key_dir / _CA_FILE),
    )

    # A new group starts at 0-0 so jobs queued before worker boot are not lost.
    ensure_consumer_groups(redis_client, streams)

    consumer = consumer_name or f"agent-{state.worker_uuid}"

    # Spawn a heartbeat thread.
    import threading

    heartbeat = HeartbeatLoop(
        control_plane_url=control_plane_url,
        worker_id=state.worker_id,
        capability_flags=capability_flags,
    )

    def _heartbeat_thread():
        while not heartbeat.stopped:
            heartbeat.tick()
            time.sleep(_HEARTBEAT_INTERVAL_SECONDS)

    hb_thread = threading.Thread(target=_heartbeat_thread, name="agent-heartbeat", daemon=True)
    hb_thread.start()

    # SIGTERM/SIGINT cleanup.
    def _stop(signum, frame):
        logger.info("received signal %s, draining locally", signum)
        heartbeat.signal_stop()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    # Lazy import: avoid circulars during static parse.
    from app.workers.sandbox_worker import process_sandbox_work

    while not heartbeat.stopped:
        if heartbeat.draining:
            logger.info("drained; exiting cleanly")
            heartbeat.signal_stop()
            break

        try:
            rows = redis_client.xreadgroup(
                SANDBOX_CONSUMER_GROUP,
                consumer,
                streams,
                block=5000,
                count=1,
            )
        except Exception as exc:  # pragma: no cover - infra
            logger.warning("xreadgroup failed: %s", exc)
            time.sleep(2)
            continue

        if not rows:
            rows = claim_stale_work_rows(
                redis_client,
                streams,
                consumer=consumer,
            )
            if not rows:
                continue

        for stream_name, messages in rows:
            if isinstance(stream_name, bytes):
                stream_name = stream_name.decode("utf-8")
            for entry_id, fields in messages:
                raw = fields.get(b"data") or fields.get("data")
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                try:
                    message = json.loads(raw or "{}")
                except json.JSONDecodeError:
                    logger.error("malformed work entry %s", entry_id)
                    redis_client.xack(stream_name, SANDBOX_CONSUMER_GROUP, entry_id)
                    continue

                run_id = int(message.get("run_id", 0))
                try:
                    with WorkEntryLease(
                        redis_client,
                        stream=stream_name,
                        consumer=consumer,
                        entry_id=entry_id,
                    ):
                        result = process_sandbox_work(
                            message,
                            worker_capabilities=normalized_capabilities,
                        )
                except Exception as exc:
                    logger.exception("process_sandbox_work failed: %s", exc)
                    # Leave entry pending so a peer can retry.
                    continue

                # Sign and publish the return payload.
                body = json.dumps(result, sort_keys=True, default=str).encode("utf-8")
                signature = _sign_payload(private_key, body)
                _publish_return(
                    redis_client,
                    run_id=run_id,
                    payload=result,
                    signature=signature,
                )

                redis_client.xack(stream_name, SANDBOX_CONSUMER_GROUP, entry_id)

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=os.environ.get("SHESHNAAG_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    parser = argparse.ArgumentParser(description="Sheshnaag V5 sandbox worker agent")
    parser.add_argument(
        "--control-plane",
        default=os.environ.get("SHESHNAAG_CONTROL_PLANE_URL", "https://control.lab.local:8443"),
        help="Control plane base URL.",
    )
    parser.add_argument(
        "--enrollment-token",
        default=os.environ.get("SHESHNAAG_WORKER_ENROLLMENT_TOKEN"),
        help="Single-use bootstrap token (only required on first boot).",
    )
    parser.add_argument(
        "--capability-flag",
        action="append",
        default=[],
        help="Repeatable. e.g. --capability-flag linux-detonation",
    )
    parser.add_argument(
        "--key-dir",
        default=os.environ.get("SHESHNAAG_WORKER_KEY_DIR", str(_DEFAULT_KEY_DIR)),
    )
    parser.add_argument("--hostname", default=None, help="Override autodetected FQDN.")
    parser.add_argument("--lan-ip", default=None, help="LAN IPv4/IPv6 SAN for the worker cert.")
    args = parser.parse_args(argv)

    return run_agent(
        control_plane_url=args.control_plane,
        enrollment_token=args.enrollment_token,
        capability_flags=args.capability_flag,
        key_dir=Path(args.key_dir),
        hostname=args.hostname,
        lan_ip=args.lan_ip,
    )


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
