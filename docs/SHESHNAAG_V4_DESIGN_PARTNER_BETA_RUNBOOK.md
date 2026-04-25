# Sheshnaag V4 Design Partner Beta Runbook

**Audience:** operators launching the full V4 PRD beta for trusted design partners.
**Runtime:** Docker Compose only.
**Launch rule:** do not open beta access while `/api/v4/ops/health` reports `beta.status=blocked`.

## Access Model

- Put the host behind VPN, Tailscale, WireGuard, or an equivalent restricted network.
- Terminate TLS at the reverse proxy; do not expose the raw API, MinIO console, Redis, Postgres, Prometheus, or OTLP collector to the public internet.
- Provision named analyst accounts. Shared beta credentials are not acceptable because authorization artifacts and audit rows need actor attribution.
- Keep `AUTH_ENABLED=true`, `ENVIRONMENT=production`, and `DEPLOYMENT_PROFILE=design_partner_beta`.

## Required Secrets

Generate and store these in the deployment `.env` or your secret manager:

- `SECRET_KEY`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `MINIO_ROOT_PASSWORD`
- `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` or `GOOGLE_API_KEY`
- `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_API_VERSION`
- AWS credentials or `AWS_PROFILE` for Bedrock
- Sigstore/OIDC configuration needed by `SHESHNAAG_AUDIT_SIGNER=cosign`
- Intel-provider keys for VirusTotal, OTX, MISP, OpenCTI, Mandiant, Shodan, and abuse.ch where applicable

Never commit partner secrets or specimen material. Store quarantine data only in MinIO/S3-compatible storage.

## Pre-Launch Checklist

Run from a clean checkout:

```bash
docker compose --env-file .env config
docker compose --env-file .env up -d --build
curl -fsS http://127.0.0.1:8000/api/v4/ops/health | jq
python3 scripts/sheshnaag_beta_acceptance.py --api http://127.0.0.1:8000 --output data/release_metadata/beta-acceptance.json
bash tests/e2e/test_real_detonation.sh
bash scripts/sheshnaag_secure_host_rehearsal.sh
```

Acceptance requires:

- `beta.status=ok` in ops health.
- Real detonation completes on the hardened Linux/KVM host.
- Redis/SSE events are visible in Run Console.
- Cosign/Sigstore audit signing is configured; HMAC fallback is not acceptable.
- STIX/TAXII validation and capability deny/approve/revoke verification are archived.
- AI provider proof matrix shows non-fallback streaming output for every required provider family.

## Data Handling

- Treat every specimen as hostile and confidential.
- Cloud AI provider use requires explicit authorization through capability policy before any specimen-derived context can leave the host.
- Design partners must receive a written data-retention statement. Default retention is 30 days for run telemetry and quarantine artifacts unless the engagement says otherwise.
- Before exporting STIX/TAXII or reports, review the disclosure bundle and verify the active `external_disclosure` artifact.

## Backups

- PostgreSQL: nightly `pg_dump`, weekly restore verification.
- MinIO: weekly `mc mirror` to encrypted backup storage; enable bucket versioning where available.
- Signing key material: sealed offline backup plus documented rotation ceremony.
- Release packet: archive each beta build under `data/release_metadata/` with git commit, image digests, health snapshot, test logs, and detonation evidence summary.

## Rollback

1. Freeze partner access at the reverse proxy.
2. Capture `/api/v4/ops/health`, API logs, worker logs, and the failing run/case IDs.
3. Stop frontend and worker first, then API:

```bash
docker compose stop frontend worker api
```

4. Restore the previous tagged image set and database backup.
5. Restart in dependency order: `db`, `redis`, `minio`, `otel-collector`, `api`, `worker`, `frontend`.
6. Run `python3 scripts/sheshnaag_beta_acceptance.py --api http://127.0.0.1:8000` before re-opening access.

## Support Escalation

Every support ticket must include:

- Partner name, analyst account, tenant slug, and engagement reference.
- Request ID from structured JSON logs.
- Case ID, run ID, specimen digest, or authorization artifact ID.
- `/api/v4/ops/health` snapshot.
- Worker log slice for the affected run.
- Whether the issue is data-loss, isolation, disclosure, AI-provider, or UX-impacting.
