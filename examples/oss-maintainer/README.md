# OSS Maintainer Demo Corpus

This directory contains synthetic, safe inputs for the maintainer assessment workflow.

- `demo-sbom.json`: CycloneDX-style SBOM with one Sheshnaag demo component match.
- `demo-vex.json`: VEX-style affected statement for the same synthetic component.
- `expected-assessment-summary.json`: abbreviated shape reviewers should see after running the workflow against seeded demo data.

No file in this directory contains malware, exploit code, credentials, or third-party target data.
