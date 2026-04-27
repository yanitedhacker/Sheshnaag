# OSS Program Readiness

This document summarizes what reviewers and contributors can verify before considering Project Sheshnaag for open-source maintainer support programs.

## Qualification Story

Sheshnaag helps OSS maintainers convert SBOM/VEX metadata and public advisory feeds into prioritized defensive triage, safe reports, and release-review evidence. The project is defensive-only and avoids target discovery, exploit brokerage, phishing, or weaponized public release workflows.

## Maintainer Workflow

1. Install dependencies and start the API:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

2. Run the safe end-to-end demo proof. It creates or reuses a synthetic private tenant, invokes the maintainer CLI, and writes ignored JSON output:

```bash
python scripts/sheshnaag_maintainer_demo.py \
  --output data/release_metadata/maintainer-demo-assessment.json
```

3. Run the same assessment directly when you already have a writable tenant and token:

```bash
python scripts/sheshnaag_maintainer.py assess \
  --base-url http://127.0.0.1:8000 \
  --tenant-slug <tenant> \
  --repo-url https://github.com/example/edge-gateway \
  --sbom examples/oss-maintainer/demo-sbom.json \
  --vex examples/oss-maintainer/demo-vex.json \
  --export-report \
  --json
```

4. Show a persisted assessment:

```bash
python scripts/sheshnaag_maintainer.py show \
  --base-url http://127.0.0.1:8000 \
  --tenant-slug <tenant> \
  --assessment-id <id> \
  --json
```

5. Export an existing assessment archive:

```bash
python scripts/sheshnaag_maintainer.py export \
  --base-url http://127.0.0.1:8000 \
  --tenant-slug <tenant> \
  --assessment-id <id> \
  --output sheshnaag-maintainer-assessment.zip
```

## Release Checklist

- CI passes for backend tests, frontend build, dependency audits, CodeQL, secret scan, Docker build smoke, and release rehearsal.
- `pip-audit -r requirements.txt` reports no known vulnerabilities.
- `npm --prefix frontend audit --audit-level=moderate` reports no moderate-or-higher vulnerabilities.
- Release metadata includes git SHA, dirty-state flag, audit status, Docker status, SBOM artifact paths, and test summary.
- CI uploads release metadata, maintainer demo proof, SBOM, and frontend build summaries as workflow artifacts.
- Changelog entry is present.
- Demo maintainer assessment succeeds with the safe corpus.

## Verification Commands

The following local commands are the minimum non-Docker readiness check:

```bash
.venv-v2/bin/python -m pytest -q tests/unit/test_maintainer_assessment.py
.venv-v2/bin/python -m pytest -q tests/unit/test_sheshnaag_service.py tests/unit/test_security_hashing.py tests/unit/test_audit_chain.py
.venv-v2/bin/python scripts/sheshnaag_api_smoke.py
.venv-v2/bin/python scripts/sheshnaag_frontend_smoke.py
.venv-v2/bin/python scripts/sheshnaag_migration_rehearsal.py
.venv-v2/bin/python scripts/sheshnaag_release_metadata.py --include-checks
.venv-v2/bin/python scripts/sheshnaag_maintainer_demo.py --allow-skip
.venv-v2/bin/python -m pip_audit -r requirements.txt
npm --prefix frontend audit --audit-level=moderate
npm --prefix frontend run build
git diff --check
```

Docker image build smoke is covered in CI and can be run locally when the Docker daemon is available:

```bash
docker build -f Dockerfile -t sheshnaag-api:ci .
docker build -f Dockerfile.frontend -t sheshnaag-frontend:ci .
```

If local Docker is not running, this is a local environment limitation rather than an application failure.

## Application Evidence

- Public repository: `https://github.com/yanitedhacker/Sheshnaag`
- License: MIT
- Maintainer role: primary maintainer and project owner
- Safety boundary: defensive validation, SBOM/VEX triage, evidence capture, provenance, and disclosure packaging only
- Maintainer automation: `/api/maintainer/assessments` and `scripts/sheshnaag_maintainer.py`
- Reviewer proof: `docs/OPENAI_OSS_APPLICATION_EVIDENCE.md`, CI artifacts, release metadata JSON, SBOM artifact, maintainer demo JSON, and frontend build summary
- CI/security controls: backend tests, dependency audits, frontend audit/build, CodeQL, gitleaks, SBOM generation, Docker build smoke, release rehearsal
- API credit use: grounded advisory summaries, release/security review assistance, report drafting, PR triage, and repetitive OSS maintainer workflow automation

## API Credits / Codex Use

API credits would be used for maintainer automation: grounded advisory summaries, release-note drafting, PR/security review assistance, report drafting, and safe workflow automation around SBOM/VEX triage. Codex Security access would be limited to repositories owned or administered by the maintainer.

## Public Safety Boundary

The demo corpus is synthetic and sanitized. It contains no malware samples, exploit code, credentials, or third-party target data.
