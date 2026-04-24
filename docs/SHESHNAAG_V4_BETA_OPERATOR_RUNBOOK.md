# Sheshnaag V4 Beta Operator Runbook

**Audience:** the operator on call for a Sheshnaag V4 beta cohort.
**Companion docs:** `SHESHNAAG_V4_DEPLOYMENT.md`, `SHESHNAAG_V4_BETA_GAP_CLOSURE.md`, `SHESHNAAG_V3_TO_V4_UPGRADE.md`, `SHESHNAAG_V4_TROUBLESHOOTING.md`, `LOG_SCHEMA.md`.

---

## 1. Daily checklist

Run these in order each shift:

1. `curl -s ${HOST}/api/v4/ops/health | jq` — every dependency must be `ok`,
   `configured`, or explicitly noted in §3.
2. `docker compose ps` (or the equivalent `kubectl get pods -A`) — confirm
   `api`, `worker`, `redis`, `db`, `minio`, `frontend` are healthy.
3. `docker compose logs -t api --since=1h | grep '"level":"error"'` —
   any unique errors deserve a Linear ticket.
4. Glance at the Authorization Center: artifacts about to expire are
   highlighted; rotate/revoke as needed.
5. Glance at the ATT&CK Coverage page: a sudden drop across all tactics
   usually means the AttackMapper or a launcher is misbehaving.

## 2. Standing on-call playbooks

### 2.1 Stuck run

- Surface: Run Console → run state stuck at `queued` or `running`.
- Likely cause: Redis Streams consumer lag or worker crash loop.
- Procedure:
  1. `curl -s ${HOST}/api/v4/ops/health | jq .redis` — must be `ok`.
  2. `docker compose logs -t worker --since=15m | tail -200`.
  3. Check pending count: `redis-cli XPENDING sheshnaag:sandbox:work sandbox-workers`.
  4. If a run is wedged, nudge it:
     `redis-cli XACK sheshnaag:sandbox:work sandbox-workers <entry-id>`
     and re-publish the work item.

### 2.2 Authorization chain verification fails

- Surface: `/api/v4/authorization/chain/verify` returns `ok: false`.
- Likely cause: storage corruption or someone hand-edited the audit log.
- Procedure:
  1. Page the security lead before any other action.
  2. Snapshot PostgreSQL (`pg_dump`) and the MinIO bucket.
  3. Capture `first_bad_idx` and `reason` from the verify endpoint.
  4. Do **not** roll forward. Rotate the audit signing key only after the
     security lead approves; never delete audit rows.

### 2.3 Capability denial flood

- Surface: analysts seeing "capability denied" toasts.
- Likely cause: artifact TTL expired or scope policy was reset.
- Procedure:
  1. Confirm via `/api/v4/authorization` and `/api/v4/capability/check`.
  2. If beta cohort needs a fast unblock, issue a short-TTL artifact via
     the Authorization Center with two reviewers.
  3. File a ticket if the same capability denies twice in 24 hours —
     scope policy may need an update.

### 2.4 SSE event firehose silence

- Surface: Run Console live panel shows no events.
- Likely cause: Redis lost the stream (`MAXLEN` aggressive) or the
  collector pipeline crashed.
- Procedure:
  1. `redis-cli XLEN sheshnaag:run:<run_id>:events`.
  2. Tail worker logs for `event_bus` errors.
  3. Worst case: restart the worker pool; lifecycle events will replay
     from the database when supported.

## 3. Known-acceptable warnings during beta

- `audit_signer.status=fallback_hmac` until production sigstore wiring is
  flipped on (`SHESHNAAG_AUDIT_SIGNER=cosign` + `sigstore>=3` installed).
- `lab_deps.tetragon=missing` — Tetragon is optional; eBPF tracing falls
  back to the in-tree tracer.
- `telemetry.otel=unconfigured` until OTel exporter endpoint is set.
- HMAC signing key rotation event in audit log: expected once per quarter.

## 4. Escalation

| Surface | Owner |
| --- | --- |
| Capability policy / authorization chain | Security lead |
| Sandbox worker / launcher pipeline | Lab platform lead |
| Frontend / SSE consumer | UX engineering |
| Object store (MinIO) | Infrastructure |
| Audit / signing keys | Security lead + Compliance |

When paging, include: `run_id` (or `artifact_id`), `request_id` from the
JSON log, the `/api/v4/ops/health` snapshot, and the most recent
PostgreSQL backup checkpoint timestamp.

## 5. Backup cadence

- PostgreSQL — `pg_dump` nightly into encrypted storage; verify weekly
  via `pg_restore --list`.
- MinIO — versioning is enabled; snapshot the bucket weekly via
  `mc mirror`.
- Audit signing key (HMAC) — held in a sealed envelope offline until
  Sigstore wiring lands.

## 6. Clean shutdown

```bash
docker compose stop frontend
docker compose stop api
docker compose stop worker
redis-cli SAVE
docker compose stop redis
docker compose stop minio
docker compose stop db
```

Restart in reverse order. Worker should always start *after* MinIO and
Redis are healthy.
