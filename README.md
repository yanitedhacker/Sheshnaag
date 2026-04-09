# Project Sheshnaag

Project Sheshnaag is a local-first defensive vulnerability research lab for enterprise software CVEs. It ingests live vulnerability intelligence, scores research candidates, creates constrained Kali-backed validation plans, captures evidence, generates defensive artifacts, and preserves signed provenance plus analyst credit.

This repo contains Project Sheshnaag, a defensive validation platform with operator workflows for intel, candidates, recipes, runs, evidence, artifacts, provenance, ledger, and disclosure bundles.

## What Exists Now

- Sheshnaag-first backend APIs for:
  - `/api/intel/*`
  - `/api/candidates/*`
  - `/api/recipes/*`
  - `/api/runs/*`
  - `/api/evidence/*`
  - `/api/artifacts/*`
  - `/api/provenance/*`
  - `/api/ledger/*`
  - `/api/disclosures/*`
- Constrained `docker_kali` validation provider abstraction with room for a future VM-backed provider.
- New Sheshnaag domain models for candidates, recipes, runs, evidence, artifacts, attestations, disclosure bundles, and ledger entries.
- React operator console for the core Sheshnaag workflows plus the product narrative and safety posture pages.
- Existing CVE, tenant, SBOM, VEX, asset, and graph foundations retained as applicability context.

## Current State

Sheshnaag now has a real control plane and operator surface:

- live intel, candidate triage, recipe management, run orchestration, evidence listing, artifact review, provenance, ledger, and disclosure routes
- signed run and bundle attestations using tenant-scoped Ed25519 keys
- real archive export for disclosure bundles
- a constrained Docker-backed execute path for the baseline collectors:
  - `process_tree`
  - `package_inventory`
  - `file_diff`
  - `network_metadata`
  - `service_logs`
- an explicit osquery-capable image path for `osquery_snapshot`

Reliable after this gap-fill pass:

- targeted Sheshnaag integration suites pass with `RUN_INTEGRATION_TESTS=1`
- route-level provenance, artifact review, and disclosure export flows are stable
- execute-mode smoke scripts exist for the baseline live path and the osquery path
- secure-mode Lima plans now record lifecycle, template, execute, and snapshot/revert audit metadata
- the operator console now includes a dedicated review queue across runs, evidence, artifacts, and bundles
- candidate score recalculation/backfill remains in-process and now persists execution summaries

Still deferred:

- long-running observability pipelines or external telemetry backends for Falco, Tetragon, Tracee, and PCAP
- deeper disclosure/report packaging and richer team workflow analytics beyond the current operator review queue

## Safety Posture

Sheshnaag is defensive-only.

- Allowed: controlled validation, evidence capture, detections, mitigations, provenance, disclosure bundles.
- Not allowed: target discovery, exploit brokerage, weaponized public release, phishing workflows, or offensive campaign tooling.
- Current validation path: constrained Kali-on-Docker with explicit capability drops, read-only defaults, default-deny egress planning, ephemeral workspaces, and acknowledgement gates for sensitive runs.
- Future secure mode: VM-grade Linux guest provider with stronger snapshot/revert semantics.

More detail:

- [PRD](docs/PROJECT_SHESHNAAG_PRD.md)
- [Architecture](docs/PROJECT_SHESHNAAG_ARCHITECTURE.md)
- [Safety Policy](docs/SHESHNAAG_SAFETY_POLICY.md)
- [Knowledge System](docs/SHESHNAAG_KNOWLEDGE_SYSTEM.md)
- [v2 Deployment Guide](docs/SHESHNAAG_V2_DEPLOYMENT_GUIDE.md)
- [v2 Operator Runbook](docs/SHESHNAAG_V2_OPERATOR_RUNBOOK.md)

## Architecture

```text
app/
  api/routes/          FastAPI surfaces for intel, candidates, recipes, runs, evidence, artifacts, provenance, ledger, disclosures
  core/                config, security, tenancy, database
  ingestion/           feed sync and schedulers
  lab/                 provider interfaces, docker_kali provider, collectors, artifact generation, attestation
  models/              foundational CVE/intel models plus Sheshnaag domain models
  services/            Sheshnaag application logic and retained supporting services
frontend/              marketing website
tests/                 unit and integration coverage
```

The system is split into three planes:

- Control plane: ingestion, scoring, recipes, runs, provenance, export APIs.
- Validation plane: constrained Docker-backed execution planning, execute-mode evidence collection, and an explicit osquery-capable image path.
- Knowledge plane: source preservation, project notes, MemPalace memory, and LLM-wiki style structured knowledge.

## Quick Start

### Backend

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend

```bash
npm --prefix frontend install
npm --prefix frontend run dev
```

### Tests

```bash
PYTHONPATH=. pytest -q
PYTHONPATH=. RUN_INTEGRATION_TESTS=1 pytest -q tests/integration/test_lab_lifecycle.py tests/integration/test_evidence_collectors.py tests/integration/test_provenance_and_disclosure_routes.py
npm --prefix frontend run build
```

### Smoke And Rehearsal

```bash
python scripts/sheshnaag_api_smoke.py
python scripts/sheshnaag_migration_rehearsal.py
python scripts/sheshnaag_execute_smoke.py
bash scripts/build_sheshnaag_osquery_image.sh
python scripts/sheshnaag_osquery_smoke.py
bash scripts/build_sheshnaag_tracee_image.sh
python scripts/sheshnaag_tracee_smoke.py
python scripts/sheshnaag_secure_mode_smoke.py
npm --prefix frontend run smoke:routes
bash scripts/sheshnaag_release_rehearsal.sh
bash scripts/sheshnaag_secure_host_rehearsal.sh
```

- `scripts/sheshnaag_api_smoke.py` spins up an in-memory FastAPI test surface and exercises intel, candidates, recipes, runs, evidence, artifacts, provenance, ledger, templates, and disclosure export.
- `scripts/sheshnaag_execute_smoke.py` verifies the baseline execute-mode Docker path when the Docker daemon is available.
- `scripts/build_sheshnaag_osquery_image.sh` builds the dedicated osquery-capable lab image tag used by the advanced telemetry smoke.
- `scripts/sheshnaag_osquery_smoke.py` verifies live `osquery_snapshot` capture when Docker is available and the osquery-capable image is present.
- `scripts/build_sheshnaag_tracee_image.sh` builds the trusted Tracee-capable lab image tag.
- `scripts/sheshnaag_tracee_smoke.py` verifies the supported Tracee runtime collector path when Docker is available and the Tracee image is present.
- `scripts/sheshnaag_secure_mode_smoke.py` verifies Lima-backed secure-mode execution, PCAP packaging, lifecycle audit metadata, and teardown cleanup when `limactl` is available.
- `scripts/sheshnaag_migration_rehearsal.py` builds a representative persisted SQLite baseline, runs Alembic upgrade/downgrade, and validates the new schema additions.
- `npm --prefix frontend run smoke:routes` verifies that every operator page is still wired into the route map and top-level nav.
- `scripts/sheshnaag_release_rehearsal.sh` runs backend smoke, route smoke, targeted unit/integration pytest, the execute-mode smoke scripts, and the frontend build in one repeatable pass. Docker-backed smoke steps self-skip when Docker is unavailable.
- `scripts/sheshnaag_secure_host_rehearsal.sh` is the dedicated release lane for a `limactl`-capable host and archives release metadata, migration rehearsal output, smoke logs, and secure-mode evidence summaries.

## Implementation Notes

- Simulated mode remains available for non-Docker development, but execute mode is the live validation path for Sheshnaag acceptance.
- The dedicated osquery image is an explicit opt-in path for `osquery_snapshot`; the default lab image remains the baseline constrained Kali image.
- The trusted image catalog now distinguishes baseline, osquery-capable, Tracee-capable, and secure Lima guest profiles.
- Advanced runtime collectors now emit one standardized telemetry/session envelope with bounded capture metadata, even when they degrade or skip.
- PCAP remains secure-mode-only and is exported as a bounded preview path with explicit sensitivity and export-gating metadata.
- The operator console `Review` page aggregates review blockers across runs, evidence, artifacts, and disclosure bundles.
- Candidate scoring recalculation stays in the monolith and is available through the candidates API as a persisted dry-run/apply workflow.
- Writes for Sheshnaag APIs should use a writable tenant; demo tenant reads are still useful for seeded exploration.
- The knowledge layer is intended to pair raw source preservation with an LLM-maintained wiki and MemPalace memory continuity.

## Next Steps

- Expand candidate scoring with richer OSV and GitHub Advisory normalization.
- Deepen the constrained run path into richer telemetry slices beyond `osquery_snapshot`.
- Add fuller disclosure/report packaging and richer operator review workflows.
- Introduce a future VM-backed provider for stronger secure-mode isolation without changing the recipe/run contract.
