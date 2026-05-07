# V5 Wave 1b — Worker pool MVP

**Goal:** Stand up an mTLS-bootstrapped sandbox-worker fleet over LAN. Control plane signs worker CSRs; workers pull jobs from Redis Streams over TLS; signed-artifact return via JWS.

**Architecture:** Dedicated worker-pool CA (separate from cosign). Workers generate RSA-3072 keys + CSRs on first boot, present a one-time enrollment token to the control plane, receive a signed cert, and use it both as their TLS client cert (rediss://) and as the JWS signing key for return payloads.

**Tech Stack:** `cryptography` (already a dep, used at `app/lab/attestation.py`) for x509 + CSR + signing. Stock `redis-py` with `ssl=True` for `rediss://`. SQLAlchemy + Alembic.

## File structure

| Action | File | Responsibility |
|---|---|---|
| Create | `app/migrations/versions/v5a04_worker_registry.py` | `workers` + `worker_ca_keys` tables. |
| Modify | `app/models/v2.py` *or* new module | New `Worker` + `WorkerCaKey` models. New module `app/models/worker_pool.py` keeps blast radius small. |
| Modify | `app/models/__init__.py` | Export the two new models. |
| Create | `app/services/worker_pool.py` | `WorkerCa` (CSR signing, CA load/init); `WorkerPoolService` (registry CRUD, enrollment-token mint, heartbeat receiver, drain). `EnrollmentToken` dataclass. Custom errors. |
| Create | `app/workers/sandbox_agent.py` | Worker daemon: bootstrap (CSR submission via HTTP), heartbeat publisher, signed-artifact return wrapping `process_sandbox_work`. |
| Create | `app/api/routes/workers.py` | `POST /api/v5/workers/bootstrap`, `POST /api/v5/workers/{id}/heartbeat`, `POST /api/v5/workers/{id}/drain`, `GET /api/v5/workers`. |
| Modify | `app/api/routes/__init__.py` + `app/main.py` | Register new router. |
| Modify | `app/core/event_bus.py` | Honor `rediss://` URL prefix; pass `ssl_certfile`/`ssl_keyfile`/`ssl_ca_certs` through to `redis.from_url`. |
| Create | `frontend/src/pages/WorkerFleetPage.tsx` | Fleet table: id, fingerprint, capability flags, last_heartbeat, state. Drain button (lab_lead only). |
| Modify | `frontend/src/api.ts`, `frontend/src/types.ts`, `frontend/src/components/Layout.tsx`, `frontend/src/App.tsx` | Wire the new page + typed methods + nav entry. |
| Create | `tests/unit/test_worker_pool.py` | WorkerCa CSR sign + verify, WorkerPoolService enrollment + heartbeat + drain. |

## mTLS protocol — final wire

1. **Worker first boot** (`sandbox_agent.py`):
   - If `/var/lib/sheshnaag-worker/key.pem` is absent: generate RSA-3072 private key (mode 0600).
   - Build a CSR with `cryptography.x509.CertificateSigningRequestBuilder`. Subject `CN=worker-<uuid>, O=Sheshnaag, OU=sandbox-worker`. SANs: `DNSName(hostname)`, `IPAddress(LAN ip)`.
   - Read the operator-supplied enrollment token from `SHESHNAAG_WORKER_ENROLLMENT_TOKEN` env var.
   - `POST /api/v5/workers/bootstrap` with `{enrollment_token, csr_pem, capability_flags}`.

2. **Control plane signs**:
   - `WorkerPoolService.bootstrap()` validates the token (15-min TTL, single-use, lab_lead-issued).
   - `WorkerCa.sign_csr(csr_pem)` returns the signed cert PEM. CA private key fetched from `worker_ca_keys` row (single row), KEK-decrypted via HKDF from `settings.secret_key`.
   - Insert a `workers` row: `(worker_id, cert_fingerprint, capability_flags, state="online", enrolled_at, enrolled_by)`.
   - Return `{cert_pem, ca_pem, redis_url}` to the worker.

3. **Worker connects** to Redis with `rediss://redis.lab.local:6380`, presenting `cert.pem` + `key.pem` against the `ca.pem`. Reads jobs from the existing consumer group; processes via the unchanged `process_sandbox_work`; wraps the result in JWS using its private key; `xadd` to `sheshnaag:sandbox:returns:<run_id>`.

4. **Heartbeat**: every 30 s, worker `POST /api/v5/workers/{id}/heartbeat` with current load + capability flags. Service updates `last_heartbeat`.

5. **Drain**: lab_lead issues `POST /api/v5/workers/{id}/drain`. Service flips `state=draining`. Worker polls heartbeat response; on `state=draining` it stops pulling new jobs, finishes in-flight, exits.

## Custody of CA private key

`worker_ca_keys` single-row table holds the CA cert + the encrypted private key. KEK is derived via HKDF from `settings.secret_key` with `info=b"v5/worker-pool-ca/kek"`. The CA itself is RSA-4096, generated on first run if the table is empty (lab_lead-only API path can also rotate it).

## Decisions deferred

- **Cert revocation list (CRL) or short-lived certs?** V5 uses short-lived certs (90-day). CRL machinery deferred to V6 if revocation cadence increases.
- **Worker-side pcap collection delegation.** Workers receive the same job payload; no protocol change needed in V5.

## Acceptance for W1b

- Migration v5a04 up + down clean on sqlite.
- Bootstrapping a worker via the HTTP route with a valid enrollment token returns a signed cert that verifies against the CA.
- The same cert correctly signs a JWS that the control plane verifies via the worker's enrolled fingerprint.
- Heartbeat updates `last_heartbeat`. Drain transitions worker state.
- WorkerFleetPage renders the registry table and the drain button shows / hides based on lab_lead role gate.
