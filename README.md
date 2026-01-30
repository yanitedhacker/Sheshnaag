# 🚨 CVE Threat Radar

**AI-Driven Vulnerability Intelligence & Patch Prioritization Engine**

A production-grade ML-powered system that ingests live vulnerability intelligence, predicts exploit likelihood, and prioritizes patches using ML-based risk scoring.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)
![XGBoost](https://img.shields.io/badge/XGBoost-2.0+-orange.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## 🎯 What This System Does

- **Ingests** live vulnerability data from NVD, Exploit-DB, and MITRE
- **Predicts** exploit likelihood using ML models (XGBoost)
- **Prioritizes** patches using intelligent risk scoring
- **Explains** every risk score with SHAP-based explainability

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10 or higher
- pip (Python package manager)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cve-threat-radar.git
cd cve-threat-radar

# Run the setup script (creates venv, installs deps, initializes DB)
chmod +x setup.sh
./setup.sh
```

### Running the Application

```bash
# Option 1: Use the run script
./run.sh

# Option 2: Manual start
source venv/bin/activate
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Access the Application
- **API Documentation**: http://127.0.0.1:8000/docs
- **Dashboard**: Open `frontend/index.html` in your browser

---

## 🧠 System Architecture

```
[Threat Feeds]       [NVD, Exploit-DB, MITRE]
       │
       ▼
[Ingestion + Validation]
       │
       ▼
[Feature Engineering]   ──► 40+ ML Features
       │
       ▼
[ML Risk Models]        ──► XGBoost Classifier
       │
       ▼
[Risk Aggregator]       ──► Priority Rankings
       │
       ▼
[API + Dashboard]       ──► FastAPI + Modern UI
```

---

## 📊 API Endpoints

### CVE Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/cves/` | Search CVEs with filters |
| GET | `/api/cves/{cve_id}` | Get CVE details |
| GET | `/api/cves/trending/list` | Get trending CVEs |
| GET | `/api/cves/recent/list` | Get recent CVEs |

### Risk Scoring
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/risk/priorities` | Top patch priorities |
| GET | `/api/risk/summary` | Risk summary statistics |
| GET | `/api/risk/cve/{cve_id}` | Get CVE risk score |
| POST | `/api/risk/calculate` | Trigger risk calculation |

### Assets
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/assets/` | Create asset |
| GET | `/api/assets/{id}` | Get asset details |
| POST | `/api/assets/{id}/scan` | Scan for vulnerabilities |

### Threat Feeds
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/feeds/sync/cves` | Sync from NVD |
| POST | `/api/feeds/sync/exploits` | Sync exploit data |
| GET | `/api/feeds/status` | Feed sync status |

---

## 🤖 ML Model Features

The risk prediction model uses **40+ features** including:

| Category | Features |
|----------|----------|
| **CVSS** | Base score, Attack vector, Complexity, Privileges, Impact metrics |
| **Temporal** | Days since published, Recency, Age bucket |
| **Exploit** | Exploit available, Metasploit module, PoC status, Exploit count |
| **Product** | Vendor count, Critical vendor flag, Product popularity |
| **CWE** | Vulnerability type, High-risk CWE categories |
| **Text** | RCE mentions, Privilege escalation, Injection indicators |

---

## 📁 Project Structure

```
cve-threat-radar/
├── app/
│   ├── api/routes/          # API endpoints
│   ├── core/                # Config & database
│   ├── ingestion/           # Threat feed clients
│   ├── ml/                  # Machine learning
│   ├── models/              # Database models
│   ├── services/            # Business logic
│   └── main.py              # FastAPI app
├── frontend/
│   └── index.html           # Dashboard UI
├── scripts/
│   ├── init_db.py           # Database setup
│   └── sync_feeds.py        # Feed sync utility
├── models/                  # Trained ML models
├── data/                    # Data files
├── requirements.txt         # Python dependencies
├── setup.sh                 # Setup script
├── run.sh                   # Run script
└── README.md
```

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| **Backend** | FastAPI, Python 3.10+ |
| **ML** | XGBoost, scikit-learn, SHAP |
| **Database** | SQLite (dev) / PostgreSQL (prod) |
| **Frontend** | Alpine.js, Tailwind CSS, Chart.js |
| **Monitoring** | Prometheus |

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | `sqlite:///./cve_threat_radar.db` |
| `NVD_API_KEY` | NVD API key (faster sync) | - |
| `SECRET_KEY` | Application secret | Change in production! |
| `ENVIRONMENT` | Environment name | `development` |

---

## 🧪 Testing

```bash
# Activate virtual environment
source venv/bin/activate

# Run tests
pytest

# With coverage
pytest --cov=app tests/
```

---

## 🐳 Docker (Optional)

```bash
# Build and run with Docker Compose
docker-compose up -d

# Access
# - API: http://localhost:8000
# - Dashboard: http://localhost:3000
```

---

## 🔒 Security Considerations

- API authentication ready (JWT support)
- Rate limiting on external API calls
- Input validation on all endpoints
- SQL injection prevention via SQLAlchemy ORM
- No secrets in code (environment variables)

---

## 📈 Sample Output

```json
{
  "cve_id": "CVE-2024-21762",
  "overall_risk_score": 77.65,
  "risk_level": "HIGH",
  "exploit_probability": 0.95,
  "explanation": "This vulnerability is rated as HIGH risk with a score of 77.7/100. There is a HIGH likelihood (95%) of active exploitation. Key risk factors: public exploit code is available, critical severity vulnerability (CVSS >= 9.0). RECOMMENDATION: Prioritize patching within 7 days."
}
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## 👤 Author

Built for security teams who need actionable vulnerability intelligence.

*This is production-grade ML + cybersecurity, not a toy.*
