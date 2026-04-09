# Sheshnaag v2 Operator Runbook

Last updated: 2026-04-09

## Routine checks

- Confirm `/health` is `healthy` or `degraded` only because Redis is intentionally absent in local mode.
- Confirm the release rehearsal still passes before promoting a new build.
- Review the latest disclosure exports and provenance signing metadata for unexpected verification changes.

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

## Failure triage

- Platform failure: health endpoint degraded, services not reachable, migrations broken, signing backend invalid.
- Runtime failure: provider readiness unavailable, image missing, collector capability unavailable, smoke lane failure.
- Review/export failure: artifact status lineage inconsistent, redaction notes missing, disclosure export blocked by sensitive evidence confirmation.
