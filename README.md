<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/FastAPI-0.115+-green.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/ML-XGBoost-orange.svg" alt="XGBoost">
  <img src="https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg" alt="Status">
</p>

<h1 align="center">CVE Threat Radar</h1>

<p align="center">
  <strong>AI-Powered Vulnerability Intelligence & Patch Prioritization Engine</strong>
</p>

<p align="center">
  Transform raw vulnerability feeds into actionable security decisions using machine learning.
</p>

---

## About

**CVE Threat Radar** is an enterprise-grade platform that ingests real-time CVE (Common Vulnerabilities and Exposures) data, predicts exploit likelihood using machine learning, and generates AI-driven patch schedules with full explainability.

As someone passionate about the intersection of AI and cybersecurity, I built this project to solve a real problem: security teams are drowning in vulnerability data but lack the tools to prioritize effectively. This platform bridges that gap by combining threat intelligence with predictive analytics.

### Why I Built This

Working in cybersecurity, I've seen organizations struggle with:
- **Alert fatigue** from thousands of CVEs published annually
- **Manual prioritization** that doesn't scale
- **Lack of context** for patch scheduling decisions

CVE Threat Radar addresses these challenges by applying ML to predict which vulnerabilities are most likely to be exploited, and providing clear, explainable recommendations for remediation.

---

## Features

### Core Capabilities

- **Real-time CVE Ingestion** - Automatic feeds from NVD (National Vulnerability Database) and Exploit-DB
- **ML-Based Risk Prediction** - XGBoost model predicting exploit probability with confidence intervals
- **Explainable AI** - SHAP-based feature importance for every prediction
- **Smart Patch Scheduling** - Constraint-aware optimization using OR-Tools
- **Asset Management** - Track vulnerabilities across your infrastructure
- **Interactive Dashboard** - Real-time visualization of your security posture

### Technical Highlights

| Component | Technology |
|-----------|------------|
| Backend | FastAPI, SQLAlchemy 2.0, Async Python |
| Database | PostgreSQL (prod), SQLite (dev) |
| ML Engine | XGBoost, scikit-learn, SHAP |
| Optimization | Google OR-Tools |
| Monitoring | Prometheus, Structured Logging |
| Security | JWT Auth, Rate Limiting, Security Headers |
| Deployment | Docker, Docker Compose |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose (for production deployment)
- Git

### Local Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/archffsarch/cve-threat-radar.git
   cd cve-threat-radar
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings (defaults work for local dev)
   ```

5. **Run the application**
   ```bash
   python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

6. **Access the application**
   - API Documentation: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc
   - Health Check: http://localhost:8000/health

### Production Deployment (Docker)

1. **Configure production environment**
   ```bash
   cp .env.production.example .env
   # Generate secure keys:
   # SECRET_KEY: openssl rand -base64 32
   # POSTGRES_PASSWORD: openssl rand -base64 24
   ```

2. **Start all services**
   ```bash
   docker-compose up -d
   ```

3. **Verify deployment**
   ```bash
   curl http://localhost:8000/health
   ```

Services will be available at:
- API: http://localhost:8000
- Frontend: http://localhost:3000
- Prometheus: http://localhost:9090

---

## Architecture

```
cve-threat-radar/
├── app/
│   ├── api/routes/          # REST API endpoints
│   ├── core/                # Config, security, database
│   ├── ingestion/           # NVD & Exploit-DB clients
│   ├── ml/                  # Risk prediction models
│   ├── models/              # SQLAlchemy ORM models
│   ├── patch_optimizer/     # Prioritization engine
│   ├── patch_scheduler/     # Scheduling constraints
│   └── services/            # Business logic layer
├── tests/
│   ├── unit/                # Fast, isolated tests
│   └── integration/         # Full stack tests
├── frontend/                # Dashboard UI
├── docker-compose.yml       # Production orchestration
└── requirements.txt         # Python dependencies
```

### Risk Scoring Formula

The patch prioritization engine uses a multi-axis scoring formula:

```
Priority = (Exploit Likelihood x Impact x Asset Criticality x Time Pressure) / Patch Cost
```

Where:
- **Exploit Likelihood (EL)**: ML-predicted probability of exploitation
- **Impact Score (IS)**: Derived from CVSS metrics
- **Asset Criticality Score (ACS)**: Based on asset environment and importance
- **Time Pressure Multiplier (TPM)**: Increases with vulnerability age
- **Patch Cost Score (PCS)**: Downtime, reboot requirements, rollback complexity

---

## API Reference

### Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/cves` | GET | Search and list CVEs |
| `/api/cves/{cve_id}` | GET | Get detailed CVE information |
| `/api/risk/priorities` | GET | Get prioritized vulnerability list |
| `/api/risk/calculate` | POST | Calculate risk for specific CVE |
| `/api/assets` | GET/POST | Manage asset inventory |
| `/api/patches/schedule` | POST | Generate patch schedule |
| `/health` | GET | Health check with dependencies |

For complete API documentation, visit `/docs` when running the application.

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ENVIRONMENT` | development/production | development |
| `SECRET_KEY` | JWT signing key (min 32 chars) | auto-generated |
| `DATABASE_URL` | Database connection string | sqlite:///./cve_threat_radar.db |
| `AUTH_ENABLED` | Enable JWT authentication | false |
| `RATE_LIMIT_ENABLED` | Enable rate limiting | true |
| `NVD_API_KEY` | NVD API key (optional, increases rate limit) | - |

See `.env.example` for the complete list.

---

## Running Tests

```bash
# Run all unit tests
pytest -m unit -v

# Run with coverage
pytest --cov=app tests/

# Run integration tests (requires Docker services)
RUN_INTEGRATION_TESTS=1 pytest -m integration -v
```

---

## Security Considerations

This project implements multiple security layers:

- **Authentication**: JWT-based with configurable expiration
- **Rate Limiting**: Per-IP limits with sliding window algorithm
- **Security Headers**: HSTS, CSP, X-Frame-Options, etc.
- **Input Validation**: Pydantic models with strict validation
- **CORS**: Configurable allowed origins
- **Secrets Management**: Environment-based configuration

For production deployments:
1. Enable authentication (`AUTH_ENABLED=true`)
2. Use strong, random `SECRET_KEY`
3. Configure specific CORS origins
4. Use PostgreSQL instead of SQLite
5. Enable metrics authentication

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## Roadmap

- [ ] Redis-based distributed rate limiting
- [ ] Kubernetes deployment manifests
- [ ] Additional threat feed integrations (CISA KEV, VulnDB)
- [ ] ML model retraining pipeline
- [ ] GraphQL API support
- [ ] Slack/Teams notifications

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/) for vulnerability data
- [Exploit-DB](https://www.exploit-db.com/) for exploit intelligence
- [FastAPI](https://fastapi.tiangolo.com/) for the excellent web framework
- [XGBoost](https://xgboost.readthedocs.io/) for gradient boosting
- [SHAP](https://shap.readthedocs.io/) for model explainability

---

## Author

**Archishman Paul**
*AI & Cybersecurity Engineer*

Building tools at the intersection of artificial intelligence and security. I believe that the future of cybersecurity lies in intelligent automation that augments human decision-making, not replaces it.

- GitHub: [@archffsarch](https://github.com/archffsarch)

---

<p align="center">
  <sub>Built with passion for the security community</sub>
</p>
