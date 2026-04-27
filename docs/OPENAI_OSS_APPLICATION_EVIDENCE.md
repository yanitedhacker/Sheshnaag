# OpenAI OSS Application Evidence

Copy-ready evidence for OpenAI OSS program review.

## Project Snapshot

- Public repository: `https://github.com/yanitedhacker/Sheshnaag`
- License: MIT
- Maintainer role: primary maintainer and project owner
- Project purpose: defensive-only vulnerability research and maintainer security automation for open-source and enterprise software.
- Safety boundary: SBOM/VEX triage, controlled validation, evidence capture, provenance, disclosure packaging, and safe reports only. Sheshnaag does not support target discovery, exploit brokerage, phishing, credential collection, or weaponized public release workflows.

## Maintainer Automation Workflow

- Maintainer API: `POST /api/maintainer/assessments`, `GET /api/maintainer/assessments/{id}`, and `POST /api/maintainer/assessments/{id}/export`.
- Maintainer CLI: `scripts/sheshnaag_maintainer.py` creates assessments, fetches prior results, and downloads exported report ZIPs.
- Demo corpus: `examples/oss-maintainer/` contains sanitized SBOM/VEX fixtures and expected output. It contains no malware, exploit code, credentials, or third-party target data.
- Reviewer proof: `scripts/sheshnaag_maintainer_demo.py --allow-skip` writes a sanitized JSON run record to `data/release_metadata/maintainer-demo-assessment.json`.

## CI And Security Controls

- Backend tests run on Python 3.11.
- Frontend install, route smoke, audit, and build run on Node 22.x for Vite 8 compatibility.
- Dependency audit runs `pip-audit` and `npm audit --audit-level=moderate`.
- CodeQL analyzes Python and JavaScript/TypeScript.
- Gitleaks scans for committed secrets.
- Docker build smoke covers backend and frontend images.
- SBOM generation uploads a CycloneDX JSON artifact.
- Release rehearsal runs real smoke scripts and uploads release metadata/demo proof artifacts.

## Verification Commands

```bash
.venv-v2/bin/python scripts/sheshnaag_release_metadata.py --include-checks
.venv-v2/bin/python scripts/sheshnaag_release_rehearsal.sh
.venv-v2/bin/python scripts/sheshnaag_api_smoke.py
.venv-v2/bin/python scripts/sheshnaag_frontend_smoke.py
.venv-v2/bin/python -m pytest -q tests/unit/test_maintainer_assessment.py
.venv-v2/bin/python -m pip_audit -r requirements.txt
npm --prefix frontend audit --audit-level=moderate
npm --prefix frontend run build
git diff --check
```

Docker image build smoke can be run locally when a Docker daemon is available:

```bash
docker build -f Dockerfile -t sheshnaag-api:ci .
docker build -f Dockerfile.frontend -t sheshnaag-frontend:ci .
```

If local Docker is unavailable, Docker proof remains covered by CI.

## API Credits / Codex Use

- Grounded advisory summaries for maintainer triage.
- Pull request and security advisory review assistance.
- Release note and changelog drafting from verified assessment data.
- Safe report generation from SBOM/VEX and advisory context.
- Repetitive maintainer workflow automation across owned or administered repositories.
