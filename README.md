# CVE Radar

**CVE Radar** is a production‑oriented cybersecurity and AI mini‑project that ingests real‑time vulnerability intelligence, predicts exploit likelihood with machine learning, and generates prioritized patch plans with explainability. It is intentionally designed to be scalable into a larger enterprise platform.

## Why It Matters
Security teams face thousands of new CVEs each year. CVE Radar turns raw feed data into actionable patch decisions by combining:
- **Live threat intelligence ingestion** (NVD + Exploit‑DB)
- **ML‑based exploit probability prediction** (XGBoost + feature engineering)
- **Explainable scoring** (SHAP / rule‑based fallback)
- **Patch prioritization and scheduling** with operational constraints

This repo is structured so that the pipeline can scale from local SQLite to a fully distributed stack.

## Features
- **Incremental feed ingestion** with cursor state tracking
- **FastAPI REST API** with JWT auth and rate limiting
- **Batch ML inference** for efficient scoring
- **Explainability** with SHAP / rule‑based explanations
- **Patch optimization** with dependency and reboot‑group constraints
- **Schedule persistence** for auditability
- **Prometheus metrics** with optional protection
- **Production‑ready config** (Postgres, Redis, Docker)

## Architecture (High Level)
```
Feeds (NVD/Exploit-DB)
        ↓
Incremental Ingestion + Sync State
        ↓
Feature Engineering + ML Prediction
        ↓
Risk Scoring + Explainability
        ↓
Patch Optimization + Scheduling
        ↓
API + Dashboard + Metrics
```

## Tech Stack
- **Backend**: FastAPI, SQLAlchemy
- **ML**: XGBoost, scikit‑learn, SHAP
- **Scheduler**: APScheduler
- **Optimization**: OR‑Tools
- **Data**: PostgreSQL (prod), SQLite (dev)
- **Monitoring**: Prometheus
- **Infra**: Docker / Docker Compose

## Quick Start (Local)
```bash
# Create virtual env
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run API (dev)
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open:
- API Docs: `http://127.0.0.1:8000/docs`
- Metrics: `http://127.0.0.1:8000/metrics`

## Production (Docker)
```bash
# Copy and edit production env
cp .env.production.example .env

# Start full stack
docker compose up --build
```

## Key Endpoints
- `POST /api/feeds/sync/incremental` — incremental feed sync (admin)
- `POST /api/risk/calculate` — batch scoring (admin)
- `GET /api/risk/priorities` — top CVE priorities
- `GET /api/patches/decisions` — patch decisions
- `POST /api/patches/schedule` — constraint‑aware schedule (admin)

## Scaling Roadmap (Future‑Ready)
This mini‑project is deliberately structured for growth:
1. **Queue‑based ingestion** (Celery / Kafka)
2. **Model registry + experiment tracking** (MLflow / W&B)
3. **Distributed scoring** (Spark / Ray)
4. **Advanced patch simulation** (Monte Carlo, SLA penalties)
5. **Multi‑tenant org support**

## Security Notes
- JWT auth can be enforced via `AUTH_ENABLED=true`.
- Metrics endpoint can be protected via `METRICS_REQUIRE_AUTH=true`.
- Production uses Postgres + Redis; SQLite is for local dev only.

## License
MIT

---

If you want to extend this project, the design favors modular growth: ingestion, ML, and scheduling layers are intentionally decoupled.
