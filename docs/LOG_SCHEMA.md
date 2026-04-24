# Sheshnaag V4 Log Schema

**Audience:** engineers building dashboards or alerts on top of Sheshnaag
logs, and operators wiring log ingestion into a SIEM.

When `LOG_JSON=true` (the default in any non-development environment),
every Sheshnaag process emits one JSON object per line on stdout. The
fields below are stable; additional context-specific keys may appear and
should be tolerated by downstream parsers.

---

## 1. Required fields

| Field | Type | Notes |
| --- | --- | --- |
| `event` | string | Human-readable summary, also used as the structlog event key. |
| `level` | string | `debug`, `info`, `warning`, `error`, `critical`. |
| `timestamp` | ISO-8601 string in UTC | Emitted by `structlog.processors.TimeStamper`. |
| `logger_name` | string | Module name, e.g. `app.services.malware_lab_service`. |

## 2. Request-scoped fields

These appear on every API log line via the `RequestIDMiddleware` /
`bind_log_context` plumbing:

| Field | Notes |
| --- | --- |
| `request_id` | UUID4. Mirrored to the `X-Request-ID` response header. |
| `path` | URL path. |
| `method` | HTTP method. |

Worker logs do not carry `request_id` because they are not request-scoped;
they emit `run_id` and `tenant_id` instead.

## 3. Run telemetry events

The detailed run telemetry stream uses these `type` values when emitted
into Redis Streams. Operators can also see them via the SSE stream:

- `run_queued`, `run_started`, `run_completed`, `run_failed`
  (lifecycle).
- `process_exec`, `network_conn`, `dns_query`, `syscall`
  (eBPF / Zeek collectors).
- `yara_hit`, `memory_finding`, `egress_blocked`, `snapshot_reverted`
  (post-detonation collectors).

Each event payload is a JSON object with at least:

```json
{
  "run_id": 42,
  "type": "process_exec",
  "timestamp": "2026-04-25T03:14:00Z",
  "severity": "info",
  "source": "ebpf",
  "payload": { "...event-specific keys..." }
}
```

## 4. Audit log fields

Audit log entries are not emitted as structured logs by default — they
live in PostgreSQL via `AuditLogEntry`. When you reflect them into the
log stream (e.g. via a separate exporter), preserve:

| Field | Notes |
| --- | --- |
| `idx` | Monotonic. |
| `previous_hash` | Base64. |
| `entry_hash` | Base64. |
| `actor` | Login or service principal. |
| `action` | `issue` / `approve` / `revoke` / `exercise` / `deny`. |
| `capability` | Capability key from the V4 taxonomy. |
| `artifact_id` | UUID-ish (or null for tenant-default permits). |
| `signed_at` | UTC ISO-8601. |

Do not emit `signature` or `signer_cert` to log streams — they are large
and unhelpful at log time.

## 5. Sensitive fields and redaction

The default structlog pipeline does not redact secrets. Keep the
following keys out of log calls:

- API keys (`*_API_KEY`).
- Raw specimen bytes (always reference by `sha256` digest).
- Audit signing key material.
- User passwords / tokens.

Capability `scope` values are safe to log as long as they don't carry
free-form analyst notes; use a digest or summarised form when writing to
external systems.

## 6. Sample log lines

```json
{"event":"sandbox worker consuming sheshnaag:sandbox:work","level":"info","timestamp":"2026-04-25T03:14:00.123Z","logger_name":"app.workers.sandbox_worker","group":"sandbox-workers","consumer":"sandbox-worker-12345"}
```

```json
{"event":"capability denied","level":"warning","timestamp":"2026-04-25T03:14:01.456Z","logger_name":"app.services.capability_policy","request_id":"a1b2c3","path":"/api/v4/runs","method":"POST","capability":"dynamic_detonation","reason":"no_active_artifact"}
```

## 7. Querying

In a local docker-compose deployment, JSON logs are easiest to slice with
`jq`:

```bash
docker compose logs -f api \
  | jq -c 'select(.level == "error")'

docker compose logs -t worker --since=2h \
  | jq -c 'select(.run_id == 42)'
```

In production, ship logs to your SIEM and key dashboards on
`event`, `level`, and `request_id` for trace continuity.
