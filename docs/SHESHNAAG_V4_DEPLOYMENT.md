# Project Sheshnaag — V4 Deployment Guide

**Status:** Draft (design approved; implementation pending)
**Applies to:** single-host hardened target. Multi-host / k8s deferred to V5.
**Companion docs:** `SHESHNAAG_V4_PRD.md`, `SHESHNAAG_V4_ARCHITECTURE.md`, `SHESHNAAG_V4_ROADMAP.md`, `SHESHNAAG_V4_CAPABILITY_POLICY.md`.

---

## 1. Target Host

- 16 cores / 64 GB RAM minimum for full-spectrum work (VM detonation + Volatility + eBPF telemetry + local Ollama).
- 1 TB NVMe for quarantine + reports + pgvector indices.
- Linux host with KVM + nested virt enabled (required for libvirt Windows-VM detonation).
- Docker 24+, docker-compose v2.
- libvirt + QEMU installed on host (used via the sandbox-worker; not containerized).
- nftables + dnsmasq + INetSim on host (egress enforcement + DNS sinkhole + fake internet).
- systemd available for worker supervision.

## 2. Component Topology (docker-compose)

V4 extends the existing V2 compose file at `docker-compose.yml` with four new services and redefines volumes. Approximate shape (illustrative; the actual file will be authored as part of Phase A execution):

```
sheshnaag-network (bridge)
├── db            postgres:16 with pgvector extension
├── redis         redis:7 with Streams enabled
├── minio         minio/minio — quarantine + reports store
├── api           FastAPI (unchanged port 127.0.0.1:8000)
├── frontend      Nginx serving built SPA (unchanged port 127.0.0.1:3000)
├── worker        sandbox-worker process pool (new) — consumes from Redis Streams
├── prometheus    prom/prometheus (retained)
├── otel-collector opentelemetry-collector-contrib (new)
└── ollama        ollama/ollama (optional, for local AI)
```

### Notable changes from V2 compose

- **Postgres 16 + pgvector**: image switches from `postgres:15-alpine` to `ankane/pgvector:v0.6.0-pg16` (or equivalent). Alembic migration enables the extension.
- **MinIO**: new service with two buckets provisioned on startup (`sheshnaag-quarantine`, `sheshnaag-reports`); credentials from env; lifecycle rules configured at boot.
- **Worker**: a new service running `python -m app.workers.sandbox_worker`. Supervised by docker restart policy; inside the container, `supervisord` keeps N worker instances alive. Horizontal scaling within a single host by raising the instance count.
- **OpenTelemetry collector**: central span / log aggregation point; exports to Prometheus + optional OTLP to an external trace backend.
- **Ollama**: optional local LLM host. Off by default; operator opts in via compose profile `--profile local-ai`.

### Services NOT containerized

- **libvirt + QEMU**: run on the host; the worker talks to them via `libvirt` socket mounted into the worker container.
- **nftables / dnsmasq / INetSim / FakeNet-NG**: host-level packages. The egress_enforcer invokes host-side binaries via `nsenter` or privileged socket.
- These are outside the compose boundary for security — isolating the sandbox from the control plane is a primary design goal.

## 3. Environment Variables

Superset of V2's env contract. Existing vars (`POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `SECRET_KEY`, `SIGNING_KEY_DIR`, etc.) stay.

### New required vars

| Var | Purpose |
|---|---|
| `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` | Quarantine store admin creds. |
| `MINIO_ENDPOINT` | Internal URL (e.g. `http://minio:9000`). |
| `MINIO_QUARANTINE_BUCKET` / `MINIO_REPORTS_BUCKET` | Bucket names. |
| `REDIS_STREAMS_NS` | Namespace prefix for streams (default `sheshnaag`). |
| `AUDIT_SIGNING_KEY` | Path to Sigstore / cosign key used to sign authorization artifacts + audit entries. |
| `REKOR_ANCHOR_ENABLED` | `true|false` — publish Merkle roots to Rekor. |
| `CAPABILITY_POLICY_BUNDLE` | Path to the policy bundle file (declares which capabilities are `tenant_default`). |

### New AI-provider vars (all optional — at least one required)

| Var | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Claude. |
| `OPENAI_API_KEY` | OpenAI. |
| `GOOGLE_API_KEY` | Gemini. |
| `AZURE_OPENAI_ENDPOINT` / `AZURE_OPENAI_API_KEY` / `AZURE_OPENAI_API_VERSION` | Azure OpenAI. |
| `AWS_REGION` / `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (or IAM role) | Bedrock. |
| `OLLAMA_HOST` / `VLLM_HOST` | Local providers. |

### New intel-fabric vars (optional per connector)

`MISP_URL` + `MISP_KEY`, `VT_API_KEY`, `OTX_API_KEY`, `ABUSECH_AUTH_KEY`, `OPENCTI_URL` + `OPENCTI_TOKEN`, `MANDIANT_API_KEY`, `SHODAN_API_KEY`.

## 4. First-Run Bootstrap

```bash
# 1. Clone and prep
git clone … sheshnaag
cd sheshnaag
cp .env.v4.example .env
$EDITOR .env   # fill required vars

# 2. Generate signing key (one-time, only if SIGNING_KEY_BACKEND=mounted-secret)
./scripts/v4/generate_audit_signing_key.sh

# 3. Pull images
docker compose pull

# 4. Start control plane
docker compose up -d db redis minio otel-collector prometheus

# 5. Initial schema + extensions (Alembic handles pgvector CREATE EXTENSION)
docker compose run --rm api alembic upgrade head

# 6. Provision MinIO buckets + lifecycle rules
docker compose run --rm api python -m app.bootstrap.minio_provision

# 7. Seed default scope policies + tenant
docker compose run --rm api python -m app.bootstrap.seed_defaults

# 8. Start API + worker + frontend
docker compose up -d api worker frontend

# 9. (Optional) Local AI
docker compose --profile local-ai up -d ollama
docker compose exec ollama ollama pull llama3.3:70b-instruct-q5_K_M

# 10. Host-side egress enforcement
sudo ./scripts/v4/install_host_egress.sh    # installs nftables rules, dnsmasq profile, INetSim
sudo systemctl enable --now sheshnaag-egress-enforcer
```

## 5. First Operator Checklist

After bootstrap, perform in order:

1. **Verify audit chain** — `docker compose exec api sheshnaag audit verify` exits 0 on an empty chain. This confirms the signing key is loaded.
2. **Issue tenant admin** — via `scripts/v4/bootstrap_tenant_admin.py`. Stores the admin account as the root of capability policy.
3. **Set tenant-default capabilities** — `AuthorizationCenterPage → Tenant Defaults`. Typically `dynamic_detonation` = tenant-default, `cloud_ai_provider_use` = tenant-default, others off.
4. **Issue capability artifacts as needed** — e.g. `external_disclosure` for a coming partner share, with two-reviewer sign-off.
5. **Test AI providers** — visit `/api/v3/ai/providers` and confirm each configured provider returns `healthy: true`.
6. **Dry-run detonation** — submit EICAR-class benign specimen; confirm the sandbox worker picks it up, snapshot is taken, pcap captured, Volatility runs, Zeek runs, `BehaviorFinding` rows appear with non-synthetic confidences.
7. **Verify egress enforcement** — attempt an outbound connection from inside the sandbox to a disallowed host; nftables rejects it; the deny shows up in the run's egress log.

## 6. Backup and Recovery

- **Postgres**: `pg_dump` snapshot; restore with `pg_restore`. The pgvector extension must be enabled in the target DB before restore.
- **MinIO**: `mc mirror` to an off-host bucket on schedule. Quarantine retention governed by MinIO lifecycle rules (default 90 days; overridable per tenant).
- **Audit chain**: included in the Postgres dump. Verify with `sheshnaag audit verify` after restore.
- **Authorization artifact signing key**: backed up separately in an encrypted secrets vault (never in Postgres); loss requires rotating signers and reissuing all active artifacts.
- **Rekor anchor** (if enabled): provides external attestation — helpful for demonstrating that the audit chain hasn't been rewritten during an outage or incident.

## 7. Upgrading V3 → V4

V4 is an additive-then-replacing upgrade:

1. Apply Phase A migrations — introduces new tables (`authorization_artifacts`, `audit_log_entries`, `ai_agent_steps`, vector columns). **Existing V3 data preserved.**
2. The `BLOCKED_PROMPT_PATTERNS` constant is deleted; any automation relying on the old blocklist must be updated to issue artifacts instead.
3. Custom-POST AI bridges (if any operator built one against V3's old harness) become obsolete — V4 speaks native wire formats.
4. SQLite dev databases remain compatible but production ops must migrate to Postgres.
5. Quarantine files under `/tmp/sheshnaag_quarantine` must be migrated to MinIO. Bootstrap script `scripts/v4/migrate_quarantine_to_minio.py` performs the move with digest verification.

## 8. Security Posture

| Area | Control |
|---|---|
| Control-plane ports | Bound to `127.0.0.1` only (existing V2 practice retained). Front the UI with an external TLS reverse proxy if remote access is required. |
| Signing keys | Mounted-secret backend by default; HSM / KMS backends planned. Keys never in DB or compose env. |
| Audit chain | Append-only via Postgres trigger; Merkle-chained; cosign-signed entries. |
| Sandbox isolation | libvirt VMs for PE/MSI; hardened docker containers otherwise. Separate network namespace + nftables kernel enforcement. |
| Egress | Default-deny; sinkhole / fake-internet profiles; `network_egress_open` capability required to lift. |
| Specimen privacy | Quarantine stays on-host by default; sending specimens to cloud AI providers requires explicit capability unlock. |
| PII | `aidefence` MCP scrubber at ingest; optional per-tenant redaction rules. |
| Observability | OpenTelemetry trace IDs carried into every audit entry for correlation; Prometheus metrics unauthenticated within `sheshnaag-network` only. |

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| All AI providers show `unconfigured` | No provider env vars set | Set at least one `*_API_KEY` or start Ollama |
| Detonation fails with "snapshot_manager unavailable" | libvirt socket not mounted into worker | Mount `/var/run/libvirt` into the worker container |
| `dynamic_detonation` denied unexpectedly | Capability not tenant-default and no artifact issued | Issue artifact or mark as tenant-default via Policy Center |
| `sheshnaag audit verify` fails | Row tampered with, or signing key rotated without artifact reissue | Investigate the failing index; restore from Postgres snapshot |
| Egress not enforced | Host-side `sheshnaag-egress-enforcer` service not running | `systemctl status sheshnaag-egress-enforcer`; restart |
| Ollama out-of-memory | Selected model too large for available VRAM | Pull a smaller quant (`q4_K_M`) or disable local AI |

## 10. V5 Preview (not in scope)

V5 will introduce:
- Multi-host worker fleets with a control-plane / data-plane split.
- External identity brokering (OIDC IdP federation).
- Cross-tenant federation for partner intel sharing.
- Bare-metal "red zone" worker provisioning for highest-risk exploit validation.
- Hardware-anchored attestation (TPM / SEV-SNP) for worker identity.
