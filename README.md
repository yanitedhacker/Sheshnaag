# CVE Threat Radar

> AI-Driven Vulnerability Intelligence & Patch Prioritization Engine

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.0+-orange.svg)](https://xgboost.readthedocs.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

### About the Creator

**Archishman Paul** proudly presents this project as part of an ever-growing journey in AI engineering. This isn't just another security tool—it's a culmination of passion for machine learning, cybersecurity, and building systems that make a real-world impact. Every line of code here reflects a commitment to understanding how AI can transform vulnerability management from reactive firefighting into proactive defense.

*"The best way to predict the future is to build it."* — This project embodies that philosophy.

---

A production-grade machine learning system that aggregates vulnerability intelligence from multiple threat feeds, predicts exploit likelihood using ensemble ML models, and generates prioritized patch recommendations with explainable risk scores.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Machine Learning Pipeline](#machine-learning-pipeline)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)

## Overview

CVE Threat Radar addresses a critical challenge in enterprise security operations: **vulnerability prioritization at scale**. With thousands of CVEs published annually, security teams need intelligent systems to identify which vulnerabilities pose the greatest risk to their infrastructure.

### Key Capabilities

- **Multi-source Intelligence Aggregation**: Ingests data from NVD, Exploit-DB, and MITRE ATT&CK
- **ML-Based Exploit Prediction**: XGBoost classifier trained on 40+ engineered features
- **Explainable Risk Scores**: SHAP-based feature attribution for every prediction
- **Asset-Aware Prioritization**: Maps vulnerabilities to organizational infrastructure
- **Real-time API**: RESTful endpoints for integration with existing security tooling

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           DATA INGESTION LAYER                          │
├─────────────────┬─────────────────┬─────────────────┬──────────────────┤
│   NVD Client    │  Exploit-DB     │  MITRE ATT&CK   │  Feed Aggregator │
│   (CVE Data)    │  (PoC/Exploits) │  (TTPs)         │  (Orchestration) │
└────────┬────────┴────────┬────────┴────────┬────────┴────────┬─────────┘
         │                 │                 │                 │
         └─────────────────┴────────┬────────┴─────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        FEATURE ENGINEERING LAYER                        │
├─────────────────┬─────────────────┬─────────────────┬──────────────────┤
│  CVSS Features  │ Temporal Features│ Exploit Features│  Text Features  │
│  (14 features)  │  (6 features)   │  (7 features)   │  (10 features)  │
└────────┬────────┴────────┬────────┴────────┬────────┴────────┬─────────┘
         │                 │                 │                 │
         └─────────────────┴────────┬────────┴─────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          ML PREDICTION LAYER                            │
├─────────────────────────────┬───────────────────────────────────────────┤
│     XGBoost Classifier      │         Heuristic Fallback Model          │
│   (Exploit Probability)     │      (Rule-based Risk Estimation)         │
└──────────────┬──────────────┴──────────────────┬────────────────────────┘
               │                                 │
               └────────────────┬────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        RISK AGGREGATION ENGINE                          │
├─────────────────┬─────────────────┬─────────────────┬──────────────────┤
│ Overall Score   │ Component Scores│ Priority Ranking│ SHAP Explanation │
│ Calculation     │ (Impact/Exposure)│ Generation     │ Generation       │
└────────┬────────┴────────┬────────┴────────┬────────┴────────┬─────────┘
         │                 │                 │                 │
         └─────────────────┴────────┬────────┴─────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           API & PRESENTATION                            │
├─────────────────┬─────────────────┬─────────────────┬──────────────────┤
│  FastAPI REST   │   Dashboard UI  │    Prometheus   │  Asset Manager   │
│   Endpoints     │  (Alpine.js)    │    Metrics      │   Integration    │
└─────────────────┴─────────────────┴─────────────────┴──────────────────┘
```

## Features

### Vulnerability Intelligence
- Automated CVE ingestion from National Vulnerability Database (NVD)
- Exploit code correlation from Exploit-DB
- CVSS v3.1 parsing with full vector decomposition
- CWE weakness categorization and risk mapping

### Machine Learning
- **40+ engineered features** across CVSS, temporal, exploit, product, and text domains
- **XGBoost gradient boosting** for exploit probability prediction
- **Heuristic fallback** for cold-start scenarios
- **SHAP explainability** for model interpretability

### Risk Scoring
- Composite risk score (0-100) combining multiple factors
- Risk level classification (CRITICAL, HIGH, MEDIUM, LOW)
- Confidence intervals for prediction uncertainty
- Natural language explanations for each score

### Asset Management
- Software inventory tracking with CPE matching
- Vulnerability-to-asset mapping
- Organization-wide risk aggregation
- Patch status workflow management

## Installation

### Prerequisites

- Python 3.10 or higher
- pip package manager
- 4GB RAM minimum (8GB recommended for ML operations)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/cve-threat-radar.git
cd cve-threat-radar

# Run automated setup
chmod +x setup.sh
./setup.sh
```

The setup script will:
1. Create a Python virtual environment
2. Install all dependencies including ML libraries
3. Initialize the SQLite database
4. Generate sample data for demonstration

### Manual Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env

# Initialize database
python scripts/init_db.py
```

## Usage

### Starting the Application

```bash
# Using the run script
./run.sh

# Or manually
source venv/bin/activate
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Accessing the Application

| Interface | URL |
|-----------|-----|
| Dashboard | http://127.0.0.1:8000/dashboard |
| API Documentation (Swagger) | http://127.0.0.1:8000/docs |
| API Documentation (ReDoc) | http://127.0.0.1:8000/redoc |
| Prometheus Metrics | http://127.0.0.1:8000/metrics |

### Example API Requests

```bash
# Get top patch priorities
curl http://127.0.0.1:8000/api/risk/priorities?limit=10

# Search CVEs by keyword
curl "http://127.0.0.1:8000/api/cves/?keyword=remote%20code%20execution"

# Get risk score for specific CVE
curl http://127.0.0.1:8000/api/risk/cve/CVE-2024-21762

# Trigger feed synchronization
curl -X POST http://127.0.0.1:8000/api/feeds/sync/cves?days=7
```

## API Reference

### CVE Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/cves/` | Search CVEs with filtering and pagination |
| `GET` | `/api/cves/{cve_id}` | Retrieve detailed CVE information |
| `GET` | `/api/cves/recent/list` | List recently published CVEs |
| `GET` | `/api/cves/trending/list` | List trending high-risk CVEs |
| `GET` | `/api/cves/statistics/summary` | Aggregate CVE statistics |

### Risk Scoring Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/risk/priorities` | Ranked patch priority list |
| `GET` | `/api/risk/summary` | Risk distribution summary |
| `GET` | `/api/risk/cve/{cve_id}` | Detailed risk score with explanation |
| `GET` | `/api/risk/heatmap` | Risk heatmap data for visualization |
| `POST` | `/api/risk/calculate` | Trigger batch risk calculation |

### Asset Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/assets/` | Register new asset |
| `GET` | `/api/assets/{id}` | Retrieve asset details |
| `POST` | `/api/assets/{id}/scan` | Scan asset for vulnerabilities |
| `GET` | `/api/assets/{id}/vulnerabilities` | List asset vulnerabilities |
| `PATCH` | `/api/assets/vulnerabilities/{id}` | Update vulnerability status |

### Feed Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/feeds/sync/cves` | Synchronize CVE data from NVD |
| `POST` | `/api/feeds/sync/exploits` | Synchronize exploit data |
| `GET` | `/api/feeds/status` | Feed synchronization status |

## Machine Learning Pipeline

### Feature Engineering

The system extracts 40+ features from raw CVE data:

| Category | Features | Description |
|----------|----------|-------------|
| **CVSS Metrics** | `cvss_v3_score`, `attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`, `scope`, `confidentiality_impact`, `integrity_impact`, `availability_impact` | Direct CVSS v3.1 vector components |
| **Derived CVSS** | `is_critical`, `is_high_severity`, `is_network_exploitable`, `is_easy_exploit` | Binary flags for risk thresholds |
| **Temporal** | `days_since_published`, `days_since_modified`, `age_bucket`, `is_new_cve`, `log_age` | Time-based risk factors |
| **Exploit** | `has_exploit`, `exploit_count`, `has_metasploit`, `has_poc`, `has_remote_exploit` | Exploit availability indicators |
| **Product** | `vendor_count`, `product_count`, `has_critical_vendor`, `is_multi_vendor` | Affected product characteristics |
| **CWE** | `is_high_risk_cwe`, `is_injection_cwe`, `is_auth_cwe` | Vulnerability type classification |
| **Text** | `text_remote_code_exec`, `text_privilege_escalation`, `text_sql_injection`, etc. | NLP-extracted indicators |

### Model Architecture

```
Input Features (40+)
        │
        ▼
┌───────────────────┐
│  StandardScaler   │
│  (Normalization)  │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│    XGBClassifier  │
│  - n_estimators:  │
│    200            │
│  - max_depth: 6   │
│  - learning_rate: │
│    0.1            │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Exploit          │
│  Probability      │
│  (0.0 - 1.0)      │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Risk Score       │
│  Aggregation      │
│  (0 - 100)        │
└───────────────────┘
```

### Risk Score Calculation

```
Overall Score = (0.35 × Exploit Score) + 
                (0.30 × Impact Score) + 
                (0.20 × Exposure Score) + 
                (0.15 × Temporal Score)

where:
  - Exploit Score = Exploit Probability × 100
  - Impact Score = (CVSS / 10) × 100
  - Exposure Score = f(product_count, critical_vendor)
  - Temporal Score = f(age_bucket)
```

## Project Structure

```
cve-threat-radar/
├── app/
│   ├── api/
│   │   └── routes/
│   │       ├── cve_routes.py      # CVE endpoints
│   │       ├── risk_routes.py     # Risk scoring endpoints
│   │       ├── asset_routes.py    # Asset management endpoints
│   │       └── feed_routes.py     # Feed sync endpoints
│   ├── core/
│   │   ├── config.py              # Application configuration
│   │   └── database.py            # Database connection management
│   ├── ingestion/
│   │   ├── nvd_client.py          # NVD API client
│   │   ├── exploitdb_client.py    # Exploit-DB client
│   │   └── feed_aggregator.py     # Feed orchestration
│   ├── ml/
│   │   ├── feature_engineering.py # Feature extraction
│   │   ├── risk_predictor.py      # ML model wrapper
│   │   └── explainer.py           # SHAP explanations
│   ├── models/
│   │   ├── cve.py                 # CVE data model
│   │   ├── exploit.py             # Exploit data model
│   │   ├── risk_score.py          # Risk score model
│   │   └── asset.py               # Asset data model
│   ├── services/
│   │   ├── cve_service.py         # CVE business logic
│   │   ├── risk_aggregator.py     # Risk calculation engine
│   │   └── asset_service.py       # Asset management logic
│   └── main.py                    # FastAPI application entry
├── frontend/
│   └── index.html                 # Dashboard SPA
├── scripts/
│   ├── init_db.py                 # Database initialization
│   └── sync_feeds.py              # Manual feed sync utility
├── models/                        # Trained ML model artifacts
├── data/                          # Data files
├── tests/                         # Test suite
├── requirements.txt               # Python dependencies
├── setup.sh                       # Automated setup script
├── run.sh                         # Application launcher
├── docker-compose.yml             # Container orchestration
├── Dockerfile                     # Container image definition
└── README.md
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | `sqlite:///./cve_threat_radar.db` |
| `NVD_API_KEY` | NVD API key for increased rate limits | - |
| `SECRET_KEY` | Application secret for security | (required in production) |
| `ENVIRONMENT` | Runtime environment | `development` |
| `DEBUG` | Enable debug mode | `true` |
| `MODEL_PATH` | Path to ML model artifacts | `./models` |
| `FEED_UPDATE_INTERVAL_HOURS` | Auto-sync interval | `6` |

### Database Support

- **Development**: SQLite (default, zero configuration)
- **Production**: PostgreSQL (recommended for concurrent access)

```bash
# PostgreSQL configuration
DATABASE_URL=postgresql://user:password@localhost:5432/cve_threat_radar
```

## Deployment

### Docker

```bash
# Build and run with Docker Compose
docker-compose up -d

# Services:
# - API: http://localhost:8000
# - Frontend: http://localhost:3000
# - Prometheus: http://localhost:9090
```

### Production Considerations

1. **Database**: Use PostgreSQL with connection pooling
2. **Caching**: Enable Redis for API response caching
3. **Security**: Configure proper CORS origins and API authentication
4. **Monitoring**: Set up Prometheus alerting rules
5. **Scaling**: Deploy behind a load balancer for high availability

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/enhancement`)
3. Commit changes (`git commit -m 'Add enhancement'`)
4. Push to branch (`git push origin feature/enhancement`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
pytest

# Run with auto-reload
uvicorn app.main:app --reload
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author

**Archishman Paul**  
AI Engineer | Security Enthusiast | Builder

This project represents my belief that the intersection of AI and cybersecurity holds immense potential. Building CVE Threat Radar taught me that real-world ML isn't about perfect models—it's about understanding the problem deeply, engineering meaningful features, and creating systems that security teams can actually trust and use.

If you find this project useful or have ideas to make it better, I'd love to connect.

---

**Disclaimer**: This tool is intended for authorized security assessments and vulnerability management. Users are responsible for ensuring compliance with applicable laws and organizational policies.

---

<p align="center">
  <i>Crafted with curiosity and countless cups of coffee.</i><br>
  <b>Archishman Paul © 2024</b>
</p>
