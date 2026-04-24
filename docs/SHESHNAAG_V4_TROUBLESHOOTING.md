# Sheshnaag V4 Troubleshooting

**Audience:** engineers debugging Sheshnaag V4 problems.
**Companion docs:** `SHESHNAAG_V4_BETA_OPERATOR_RUNBOOK.md`, `LOG_SCHEMA.md`, `SHESHNAAG_V4_BETA_GAP_CLOSURE.md`.

---

## 1. Diagnostic preamble

When opening a ticket, capture:

- A `request_id` from the JSON log (every API response also returns it via
  the `X-Request-ID` header).
- The `/api/v4/ops/health` snapshot.
- The relevant `run_id`, `artifact_id`, `case_id`, or `specimen_id`.

`grep '"request_id":"<value>"'` across the JSON log finds every event for
a single request, including DB queries and emitted SSE events.

## 2. Symptom → likely cause

### 2.1 `capability_denied:no_active_artifact`

- Cause: no authorization artifact covers `(capability, scope)` for the
  caller, and the tenant default does not list the capability either.
- Fix: issue an artifact via Authorization Center, OR have an admin add
  the capability to the tenant's `ScopePolicy.tenant_default_capabilities`.

### 2.2 `redis_unavailable_for_eventbus`

- Cause: Redis went away. EventBus auto-falls back to an in-memory ring
  buffer for tests; production must alert.
- Fix: bring Redis back; the worker will rejoin the consumer group
  automatically.

### 2.3 `MinIO bucket does not exist`

- Cause: provisioning script never ran on this host.
- Fix: `python scripts/v4/minio_provision.py` — idempotent.

### 2.4 SSE stream stalls after `: connected`

- Cause: Redis `XADD` succeeded but `XREAD` is blocked, usually because
  the publisher uses `xadd` to a stream the subscriber never created.
- Fix: confirm the publisher is using `run_event_stream(run_id)`; the
  subscriber must subscribe to the same stream key.

### 2.5 `signature_invalid` from `/authorization/chain/verify`

- Cause: signing key was rotated without re-issuing the in-flight
  artifacts, OR an audit row was tampered with.
- Fix: page security lead. Don't `DELETE` audit rows; they are
  append-only and the chain detects deletion as a hash mismatch.

### 2.6 Frontend renders blank dashboard

- Cause: `/api/dashboard` is failing because `feed_scheduler` blocked the
  startup. Common after upgrading from V3.
- Fix: `docker compose logs api | head -100` — fix any startup error
  surfaced there. Re-running migrations is safe.

### 2.7 `OBJECT_STORE_BACKEND=minio` but health says `filesystem`

- Cause: the MinIO env vars are missing (`MINIO_ENDPOINT`,
  `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`) or the MinIO host is
  unreachable. The factory falls back to filesystem on import error.
- Fix: confirm env vars, then restart the API/worker.

### 2.8 ATT&CK coverage shows unexpected `Unknown` tactic

- Cause: the AttackMapper bundle is older than the technique IDs in use.
- Fix: refresh the bundle via
  `python scripts/v4/fetch_attack_data.py` and restart the API.

### 2.9 Sandbox worker process pool restart loop

- Cause: a child crashes faster than the supervisor can keep up with
  restarts.
- Fix: tail `docker compose logs worker`. Common causes: Postgres
  rejecting the worker's connection (creds rotated), Redis password
  mismatch, or the lab dependencies missing on the host.

### 2.10 Autonomous agent always returns `denied`

- Cause: no active artifact for `autonomous_agent_run`.
- Fix: issue an artifact via Authorization Center, scoped to the tenant
  and (optionally) the case.

## 3. Diagnostic helpers

```bash
# Tail JSON logs for a single request_id
docker compose logs -f api | jq -c "select(.request_id == \"$RID\")"

# Inspect a stream
redis-cli XINFO STREAM sheshnaag:run:42:events

# Verify the audit chain across the last 1k rows
curl -s ${HOST}/api/v4/authorization/chain/verify | jq

# Re-run alembic
${PYTHON_BIN:-python3} -m alembic upgrade head
```

## 4. Known-flaky tests

- `tests/integration/test_malware_lab_routes.py` — relies on a committed
  seed. If it fails on a fresh checkout, run `python -m pytest -q
  tests/integration/test_malware_lab_routes.py -x` and inspect the
  fixture.

## 5. Reporting bugs

File issues in the project tracker with:

- Branch / commit SHA.
- `git status -uno`.
- Environment: container image tag or local Python version.
- Reproduction steps as a numbered list.
- Logs scrubbed of secrets (the JSON log already excludes capability
  scopes' raw payload).
