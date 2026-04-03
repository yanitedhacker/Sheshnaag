<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/FastAPI-0.115+-green.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/Frontend-React%20%2B%20Vite-orange.svg" alt="Frontend">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-V2%20Implemented-brightgreen.svg" alt="Status">
</p>

<h1 align="center">CVE Threat Radar</h1>

<p align="center">
  <strong>Exposure-Aware Vulnerability Intelligence and Remediation Decision Platform</strong>
</p>

<p align="center">
  Turn CVEs, threat intel, asset context, attack paths, and patch constraints into evidence-backed remediation decisions.
</p>

---

## About

**CVE Threat Radar** is a backend-heavy cybersecurity platform that ingests vulnerability intelligence, maps it to assets and software inventory, builds an exposure graph, and ranks remediation actions using deterministic scoring plus grounded AI explanations.

The project started as an AI-driven CVE prioritization engine and has now evolved into a **v2 exposure-aware threat radar** with:

- tenant-scoped operational context
- public demo and private workspaces
- attack-path-aware ranking
- grounded copilot responses with citations
- model trust and feedback loops
- SBOM and VEX imports
- approval workflows and audit trails

The current implementation is designed to show depth in **AI, cybersecurity, and systems design** rather than just produce a basic CVE dashboard.

---

## What V2 Does

### Core Platform

- **Threat Feed Aggregation**: Ingests CVE and exploit intelligence from NVD and Exploit-DB.
- **Threat Intel Enrichment**: Adds KEV, EPSS, ATT&CK mappings, advisory notes, and recommendation documents.
- **Asset and Software Context**: Tracks assets, services, identities, network exposure, and normalized software inventory.
- **Exposure Graph**: Persists graph nodes and edges for assets, services, identities, software components, CVEs, and patches.
- **Actionable Risk Scoring**: Ranks remediation actions by combining exploit probability, public exposure, crown-jewel context, path reachability, VEX posture, and operational patch cost.
- **Simulation Workbench**: Runs what-if patch scenarios with delay, downtime, team capacity, windows, and compensating controls.

### Phase 2 Capabilities

- **Grounded Copilot**: Answers supported security questions using structured retrieval plus cited source-backed context.
- **Model Trust Center**: Shows calibration buckets, feature importance, drift against EPSS, score history, retrieval coverage, and analyst feedback trends.
- **Analyst Feedback Loop**: Allows human feedback to influence trust and recommendation presentation without turning ranking into an opaque black box.

### Phase 3 Capabilities

- **Private Tenant Onboarding**: Create private workspaces with owner membership and JWT auth.
- **RBAC Scaffolding**: Supports tenant memberships and role-scoped access for private flows.
- **SBOM Import**: Accepts CycloneDX-style component, service, and dependency data.
- **VEX Import**: Accepts VEX/OpenVEX-style statements and feeds them into visibility and recommendation confidence.
- **Approvals and Audit Trail**: Stores patch approvals, sign-offs, analyst decisions, and append-only audit events.

---

## Technical Highlights

| Component | Technology |
|-----------|------------|
| Backend | FastAPI, SQLAlchemy 2.0 |
| Frontend | React 18, TypeScript, Vite, TanStack Query, React Router |
| Database | PostgreSQL-first design, SQLite-compatible local/dev runtime |
| Caching | Redis |
| ML / Risk | XGBoost-compatible predictor, scikit-learn, heuristic fallback |
| Threat Intel | KEV, EPSS, ATT&CK, advisory knowledge documents |
| Graphing | Persisted exposure graph with Python path search |
| Governance | JWT auth, tenant memberships, approvals, audit chain |
| Deployment | Docker, Docker Compose, Nginx frontend image |

---

## Product Surfaces

The frontend operator console includes:

- **Workbench**: ranked remediation actions with signals, evidence, citations, approvals, and analyst feedback
- **Attack Graph**: persisted graph nodes, edges, and top attack paths
- **Simulator**: what-if patch planning with scheduling constraints
- **Asset Explorer**: asset inventory and vulnerability drill-down
- **Trust Center**: model trust, calibration, drift, retrieval coverage, and feedback loop visibility
- **Operations**: private tenant provisioning plus sample SBOM/VEX workflows

---

## Architecture

```text
cve-radar/
├── app/
│   ├── api/routes/          # FastAPI endpoints
│   ├── core/                # Config, auth, cache, tenancy, database
│   ├── ingestion/           # Feed clients and scheduler
│   ├── ml/                  # Risk predictor and explainer
│   ├── models/              # Core and v2 SQLAlchemy models
│   ├── patch_optimizer/     # Patch-centric scoring engine
│   ├── patch_scheduler/     # Scheduling constraints and planner
│   └── services/            # Workbench, graph, import, governance, auth, copilot
├── frontend/                # React + Vite operator console
├── tests/
│   ├── unit/
│   └── integration/
├── docker-compose.yml
└── requirements.txt
```

### Key Domain Split

- **Global intel**: CVEs, exploits, KEV, EPSS, ATT&CK techniques, advisory documents, patch catalog
- **Tenant-scoped context**: assets, services, software components, network exposure, identities, simulations, feedback, approvals, and audit events

### Exposure Graph Model

Node types:

- `asset`
- `service`
- `identity`
- `software_component`
- `cve`
- `patch`

Edge types:

- `runs`
- `exposes`
- `depends_on`
- `reachable_from`
- `authenticates_to`
- `contains_vulnerability`
- `mitigated_by`

---

## Actionable Risk Model

The v2 workbench ranks remediation actions by fusing:

- patch optimizer priority
- stored risk scores and exploit probability
- KEV membership
- EPSS score
- exploit availability
- public exposure
- crown-jewel and business criticality
- exposure graph path reachability
- time pressure
- VEX status
- analyst feedback and governance state

The result is a deterministic recommendation object with:

- `actionable_risk_score`
- `recommended_action`
- `confidence`
- `confidence_band`
- `evidence[]`
- `citations[]`
- `approval_state`
- `feedback_summary`

---

## API Overview

### Existing Core APIs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/cves` | GET | Search and list CVEs |
| `/api/cves/{cve_id}` | GET | Detailed CVE info plus intel enrichments |
| `/api/risk/priorities` | GET | Ranked vulnerability priorities |
| `/api/assets` | GET/POST | List or create assets |
| `/api/patches/{patch_id}` | GET | Patch detail with mappings and approvals |
| `/api/dashboard` | GET | Aggregated demo dashboard data |

### V2 APIs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/workbench/summary` | GET | Ranked remediation actions |
| `/api/graph/attack-paths` | GET | Exposure graph snapshot and top attack paths |
| `/api/simulations/risk` | POST | What-if simulation run |
| `/api/copilot/query` | POST | Grounded security Q&A |
| `/api/model/trust` | GET | Trust center snapshot |
| `/api/model/feedback` | GET/POST | Analyst feedback loop |
| `/api/governance/approvals` | GET/POST | Patch approvals and sign-offs |
| `/api/governance/audit` | GET | Append-only audit events |
| `/api/tenants` | GET | List visible tenants |
| `/api/tenants/onboard` | POST | Create private tenant |
| `/api/auth/token` | POST | Login for private tenant users |
| `/api/auth/me` | GET | Inspect current authenticated user |
| `/api/imports/sbom` | POST | Import SBOM data for private tenant |
| `/api/imports/vex` | POST | Import VEX/OpenVEX data for private tenant |

For complete endpoint details, run the app and visit `/docs`.

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Git
- Docker and Docker Compose for containerized runs

### Backend

1. **Clone the repository**
   ```bash
   git clone https://github.com/yanitedhacker/CVE-Radar.git
   cd CVE-Radar
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```

3. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Create environment file**
   ```bash
   cp .env.example .env
   ```

5. **Run the backend**
   ```bash
   python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

### Frontend

1. **Install frontend dependencies**
   ```bash
   npm --prefix frontend install
   ```

2. **Run the frontend dev server**
   ```bash
   npm --prefix frontend run dev
   ```

3. **Build the frontend**
   ```bash
   npm --prefix frontend run build
   ```

### Local URLs

- Backend API docs: http://localhost:8000/docs
- Backend ReDoc: http://localhost:8000/redoc
- Health check: http://localhost:8000/health
- Frontend dev server: http://localhost:5173
- Backend-served built dashboard: http://localhost:8000/dashboard

### Demo Workspace

On startup, the app seeds a read-only public tenant:

- `demo-public`

It includes:

- sample assets and vulnerabilities
- seeded attack paths
- KEV/EPSS/ATT&CK enrichments
- patch recommendations
- trust center data
- governance artifacts

---

## Docker

You can still use Docker Compose for a full local stack:

```bash
docker-compose up -d
```

The repository also includes a dedicated frontend image build in [Dockerfile.frontend](Dockerfile.frontend).

---

## Testing

Run backend unit tests:

```bash
PYTHONPATH=. pytest -m unit -q
```

Build the frontend:

```bash
npm --prefix frontend run build
```

Optional integration tests:

```bash
RUN_INTEGRATION_TESTS=1 pytest -m integration -v
```

---

## Configuration Notes

Important settings live in [app/core/config.py](app/core/config.py).

Examples include:

- `DATABASE_URL`
- `REDIS_URL`
- `AUTH_ENABLED`
- `SECRET_KEY`
- `MODEL_PATH`
- `AI_GATEWAY_MODE`
- `DEFAULT_EMBEDDING_MODEL`
- `FEED_UPDATE_INTERVAL_HOURS`

See [`.env.example`](.env.example) and [`.env.lab.example`](.env.lab.example) for example values.

---

## Security Notes

This project includes:

- JWT auth support
- rate limiting
- security headers
- CORS controls
- tenant isolation
- approval workflows
- append-only audit history
- grounded explanation design so the LLM does not make ranking decisions

For production use:

1. enable auth
2. use strong secrets
3. set explicit CORS origins
4. prefer PostgreSQL and Redis
5. review tenant access controls
6. keep secret scanning and push protection enabled in GitHub

---

## Roadmap

Likely next steps:

- replace placeholder retrieval embeddings with `pgvector` or dedicated vector search
- add hosted LLM provider integration behind the grounded AI gateway
- add background worker process for graph rebuilds and enrichment jobs
- expand ATT&CK and advisory ingestion from live official feeds
- harden multi-tenant auth and approval UX
- add end-to-end browser tests for the operator console

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

---

## Acknowledgments

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [Exploit-DB](https://www.exploit-db.com/)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST EPSS](https://www.first.org/epss/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [CycloneDX](https://cyclonedx.org/)
- [FastAPI](https://fastapi.tiangolo.com/)
- [React](https://react.dev/)
- [Vite](https://vitejs.dev/)
