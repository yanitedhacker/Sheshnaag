# V5 Smoke Runbook

End-to-end dry run for the V5 milestone on a 3-node deployment (1 control plane + 2 workers).

## Prerequisites

- Control plane: API on `:8000`, Postgres, Redis loopback `redis://127.0.0.1:6379`
- Workers: `SHESHNAAG_WORKER_ENROLLMENT_TOKEN` from lab_lead, KVM optional for V5 (required for V6 prep)
- OIDC: Keycloak + Authentik providers registered via `/api/v5/auth/oidc/providers`

## Steps

### 1. Worker pool bootstrap

```bash
# On control plane — mint enrollment token (lab_lead JWT)
curl -s -X POST http://127.0.0.1:8000/api/v5/workers/enrollment-tokens \
  -H "Authorization: Bearer $LAB_LEAD_JWT" | jq .

# On each worker
export SHESHNAAG_WORKER_ENROLLMENT_TOKEN=...
python -m app.workers.sandbox_agent
```

Verify fleet: **Workers** nav → both workers `online`, heartbeat < 60s.

### 2. Concurrent detonation load (gate item 1)

```bash
python scripts/sheshnaag_v5_gate_load_test.py \
  --api http://127.0.0.1:8000 \
  --concurrency 5 \
  --output data/release_metadata/v5-load-test.json
```

Expect: all 5 jobs dispatched in < 1s p99 from enqueue to worker pickup.

### 3. Worker reimage survival (gate item 2)

```bash
pytest tests/integration/test_worker_reimage.py -q
```

Manual: drain worker, delete `/var/lib/sheshnaag-worker/key.pem`, re-bootstrap with new enrollment token — cert fingerprint changes, worker rejoins fleet.

### 4. OIDC two-IdP login (gate item 3)

```bash
pytest tests/integration/test_oidc.py -q
```

Manual: login via Keycloak and Authentik; confirm role-gated nav (analyst cannot reach **Workers**).

### 5. Lifecycle red-team (gate item 4)

```bash
pytest tests/red_team/test_lifecycle_escapes.py -q
```

### 6. Team analytics (gate item 5)

```bash
python scripts/sheshnaag_seed_v5_analytics.py --cases 1000
```

Open **Analytics** — histograms non-empty, queue-aging heatmap renders.

## Artifacts

Store proof under `data/release_metadata/v5-gate/`:
- `load-test.json`
- `oidc-screenshots/` (optional)
- `analytics-screenshot.png`
