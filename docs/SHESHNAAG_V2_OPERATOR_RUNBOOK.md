# Sheshnaag v2 Operator Runbook

Last updated: 2026-04-09

## Routine checks

- Confirm `/health` is `healthy` or `degraded` only because Redis is intentionally absent in local mode.
- Confirm the release rehearsal still passes before promoting a new build.
- On `limactl` hosts, run `bash scripts/sheshnaag_secure_host_rehearsal.sh` before promoting a secure-mode-capable release.
- Review the latest disclosure exports and provenance signing metadata for unexpected verification changes.
- Review the operator `Review` page for blocked runs, sensitive evidence, artifact review drift, and disclosure bundles awaiting action.

## Signing key rotation

1. Back up the current `SIGNING_KEY_DIR`.
2. Generate a replacement key set in the configured backend path.
3. Restart the API so the tenant key metadata refreshes.
4. Run provenance and disclosure smoke flows to confirm verification status remains `verified`.

## Backup and recovery

- Database: back up PostgreSQL before upgrades and before changing schema-bearing code.
- Exports: preserve `SHESHNAAG_EXPORT_ROOT` alongside DB backups.
- Keys: back up `SIGNING_KEY_DIR` independently from app data.
- Release metadata: archive `RELEASE_METADATA_DIR` for each release candidate.

## Secure mode

- Standard recipes may use `docker_kali`.
- Recipes with `execution_policy.secure_mode_required=true` must use provider `lima`.
- PCAP remains secure-mode-only in v2.
- Secure-mode acceptance requires a real `launch_mode=execute` run on a `limactl` host plus archived lifecycle/snapshot/execute audit metadata.
- Review `manifest.secure_mode_audit` for host checks, template digest, boot/readiness events, execute result, and teardown/delete events.

## Candidate score backfill

- Use `POST /api/candidates/recalculate` for dry-run or applied score recalculation.
- Persisted recalculation summaries are available from `GET /api/candidates/recalculate/history`.
- Treat canonical advisory normalization, package links, and version-range linkage as the scoring source of truth.

## Failure triage

- Platform failure: health endpoint degraded, services not reachable, migrations broken, signing backend invalid.
- Runtime failure: provider readiness unavailable, image missing, collector capability unavailable, smoke lane failure.
- Review/export failure: artifact status lineage inconsistent, redaction notes missing, disclosure export blocked by sensitive evidence confirmation.
- Migration failure: run `python scripts/sheshnaag_migration_rehearsal.py` and inspect the emitted upgrade/downgrade summary before retrying.
