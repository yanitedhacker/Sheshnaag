# Sheshnaag V3 → V4 Upgrade Runbook

**Audience:** operators upgrading an existing V3 deployment to V4 beta.
**Companion docs:** `SHESHNAAG_V4_DEPLOYMENT.md`, `SHESHNAAG_V4_BETA_OPERATOR_RUNBOOK.md`, `SHESHNAAG_V4_BETA_GAP_CLOSURE.md`.

---

## 0. Prerequisites

Before upgrading:

- Take a fresh PostgreSQL backup. The V4 capability tables and IOC graph
  enrichments add new constraints; rollback to V3 requires the snapshot.
- Verify `redis>=7` is reachable. V4 uses Redis Streams for the event bus
  and Streams require Redis 5.0+.
- Provision a MinIO endpoint (or set `OBJECT_STORE_BACKEND=filesystem`
  for single-host deployments).
- Generate or rotate `SECRET_KEY`, `AUDIT_SIGNING_KEY`,
  `MINIO_ROOT_PASSWORD`, and any AI provider keys.
- Confirm the host meets the V4 detonation prerequisites: `nft`, `dnsmasq`,
  `inetsim`, `vol` (Volatility), and `zeek` (or `tetragon`). Use
  `scripts/v4/install_host_deps.sh` to install missing binaries on Ubuntu
  22.04 / Debian 12 hosts; macOS dev boxes get a partial set.

## 1. Upgrade order

1. Stop V3 traffic (block at the load balancer or shut the API container).
2. Run the V4 schema migrations:
   ```bash
   alembic upgrade head
   ```
3. Provision MinIO (idempotent):
   ```bash
   python scripts/v4/minio_provision.py
   ```
4. Migrate quarantine objects from the local filesystem fallback:
   ```bash
   python scripts/v4/migrate_quarantine_to_minio.py
   ```
   The script verifies sha-256 digests before deletion. Pass `--keep`
   while you are bedding in the new bucket policy.
5. Roll the API + worker images to V4:
   ```bash
   docker compose pull
   docker compose up -d
   ```
6. Re-enable traffic and watch `/api/v4/ops/health` for ten minutes.

## 2. Configuration deltas

V4 introduces the following environment variables — set them before the
roll:

| Variable | Default | Purpose |
| --- | --- | --- |
| `OBJECT_STORE_BACKEND` | `filesystem` | `minio` flips the quarantine into MinIO. |
| `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_BUCKET`, `MINIO_SECURE` | unset | MinIO connection. |
| `LOG_JSON` | environment-dependent | `true` switches stdlib + structlog into JSON mode. |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME` | unset | Enable OpenTelemetry tracing. |
| `SHESHNAAG_AUDIT_SIGNER` | `hmac` | `cosign` enables real Sigstore + Rekor signing. |
| `SHESHNAAG_SANDBOX_WORKER_CONCURRENCY` | `2` | Process pool size for `--supervised` worker mode. |
| `ATTACK_MAPPER_LLM_FALLBACK`, `ATTACK_MAPPER_LLM_PROVIDER` | unset | Optional LLM fallback for ATT&CK technique mapping. |
| `AUTONOMOUS_AGENT_PROVIDER` | unset | Provider used by the autonomous analyst agent for synthesis. |

Capability policy is unchanged from V3 in shape but adds two new
capabilities: `autonomous_agent_run` and (already in V3) `dynamic_detonation`.
Reviewers should issue artifacts ahead of the cutover so analysts do not
hit denials during the first hour of beta.

## 3. Surface deltas

Operators should expect the following new analyst surfaces post-upgrade:

- `Auth` — Authorization Center (issue / approve / revoke / verify chain).
- `ATT&CK` — coverage heatmap and per-technique drill-in.
- `Graph` — Case graph anchored on `AnalysisCase`.
- `Agent` — Bounded autonomous analyst agent (gated by capability).
- Run Console — live SSE event panel.

API additions are documented in §4 of
`SHESHNAAG_V4_BETA_GAP_CLOSURE.md`.

## 4. Verification

After traffic resumes, run:

```bash
RUN_INTEGRATION_TESTS=1 .venv-v2/bin/python -m pytest -q \
  tests/unit \
  tests/integration/test_malware_lab_routes.py \
  tests/integration/test_taxii_routes.py \
  tests/integration/test_v4_phase1_routes.py \
  tests/integration/test_attack_routes.py \
  tests/integration/test_case_graph_routes.py \
  tests/integration/test_autonomous_routes.py
npm --prefix frontend run smoke:routes
```

Watch `/api/v4/ops/health` for thirty minutes. The MinIO and audit-signer
fields should report `ok` + `cosign` (or `fallback_hmac` when sigstore is
not yet wired).

## 5. Rollback plan

If V4 misbehaves:

1. Block API traffic.
2. Restore PostgreSQL from the backup taken in §0.
3. Roll the container tag back to the last V3 release.
4. Run `alembic downgrade <V3_REVISION>`.
5. Leave MinIO running — the V3 path tolerates the new bucket because it
   never reads from it.

If a partial rollback is acceptable, leave V4 schema in place and only
roll the container; the V3 image will refuse to use the new tables and
will behave as before.

## 6. Known beta caveats

- Real detonation is supported but the sample E2E harness
  (`tests/e2e/test_real_detonation.sh`) requires a Linux host with KVM and
  the V4 dependency installer applied.
- HMAC signing is acceptable in `development` and `staging`; production
  beta cohorts must flip `SHESHNAAG_AUDIT_SIGNER=cosign`.
- The autonomous analyst agent is rate-limited to 10 steps per run and
  never executes shell commands; treat its summaries as drafts requiring
  reviewer sign-off.
