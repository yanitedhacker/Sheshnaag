# OSS Program Readiness

This document summarizes what reviewers and contributors can verify before considering Project Sheshnaag for open-source maintainer support programs.

## Qualification Story

Sheshnaag helps OSS maintainers convert SBOM/VEX metadata and public advisory feeds into prioritized defensive triage, safe reports, and release-review evidence. The project is defensive-only and avoids target discovery, exploit brokerage, phishing, or weaponized public release workflows.

## Maintainer Workflow

1. Start the API.
2. Authenticate to a writable tenant.
3. Run:

```bash
python scripts/sheshnaag_maintainer.py assess \
  --base-url http://127.0.0.1:8000 \
  --tenant-slug <tenant> \
  --repo-url https://github.com/example/edge-gateway \
  --sbom examples/oss-maintainer/demo-sbom.json \
  --vex examples/oss-maintainer/demo-vex.json \
  --export-report
```

4. Review the matched findings and exported report metadata.

Machine-readable run:

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

Export an existing assessment archive:

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
- CI/security controls: backend tests, dependency audits, frontend audit/build, CodeQL, gitleaks, SBOM generation, Docker build smoke, release rehearsal
- API credit use: grounded advisory summaries, release/security review assistance, report drafting, PR triage, and repetitive OSS maintainer workflow automation

## API Credits / Codex Use

API credits would be used for maintainer automation: grounded advisory summaries, release-note drafting, PR/security review assistance, report drafting, and safe workflow automation around SBOM/VEX triage. Codex Security access would be limited to repositories owned or administered by the maintainer.

## Public Safety Boundary

The demo corpus is synthetic and sanitized. It contains no malware samples, exploit code, credentials, or third-party target data.
