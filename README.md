# Project Sheshnaag

Project Sheshnaag is a local-first defensive vulnerability research lab for enterprise software CVEs. It ingests live vulnerability intelligence, scores research candidates, creates constrained Kali-backed validation plans, captures evidence, generates defensive artifacts, and preserves signed provenance plus analyst credit.

This repo is a hard pivot from CVE Threat Radar into the first Sheshnaag release. The frontend now exposes the operator console routes for intel, candidates, recipes, runs, evidence, artifacts, provenance, ledger, and disclosure bundles on top of the Sheshnaag backend APIs.

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

## Architecture

```text
app/
  api/routes/          FastAPI surfaces for intel, candidates, recipes, runs, evidence, artifacts, provenance, ledger, disclosures
  core/                config, security, tenancy, database
  ingestion/           feed sync and schedulers
  lab/                 provider interfaces, docker_kali provider, collectors, artifact generation, attestation
  models/              legacy CVE/intel models plus Sheshnaag domain models
  services/            Sheshnaag application logic and retained supporting services
frontend/              marketing website
tests/                 unit and integration coverage
```

The system is split into three planes:

- Control plane: ingestion, scoring, recipes, runs, provenance, export APIs.
- Validation plane: constrained Kali-backed execution planning and evidence collection.
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
npm --prefix frontend run build
```

### Smoke And Rehearsal

```bash
python scripts/sheshnaag_api_smoke.py
npm --prefix frontend run smoke:routes
bash scripts/sheshnaag_release_rehearsal.sh
```

- `scripts/sheshnaag_api_smoke.py` spins up an in-memory FastAPI test surface and exercises intel, candidates, recipes, runs, evidence, artifacts, provenance, ledger, templates, and disclosure export.
- `npm --prefix frontend run smoke:routes` verifies that every operator page is still wired into the route map and top-level nav.
- `scripts/sheshnaag_release_rehearsal.sh` runs the backend smoke, frontend route smoke, targeted Sheshnaag pytest suite, and frontend build in one repeatable pass.

## Implementation Notes

- Existing patch/workbench flows remain in the repo for transition safety, but they are no longer the primary product story.
- The first validation path is intentionally simulated/constrained rather than a full offensive execution framework.
- Writes for Sheshnaag APIs should use a writable tenant; demo tenant reads are still useful for seeded exploration.
- The knowledge layer is intended to pair raw source preservation with an LLM-maintained wiki and MemPalace memory continuity.

## Next Steps

- Expand candidate scoring with richer OSV and GitHub Advisory normalization.
- Deepen the constrained run path into richer evidence collection and policy packs.
- Add fuller disclosure templates and operator UX after the marketing-site phase.
- Introduce a future VM-backed provider for stronger secure-mode isolation.
