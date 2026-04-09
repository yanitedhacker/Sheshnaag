# Project Sheshnaag Architecture

## Summary

Project Sheshnaag is split into three planes:

- Control plane: FastAPI services for intel, candidate scoring, recipes, runs, provenance, and disclosure exports.
- Validation plane: constrained Docker-backed provider abstraction with execute-mode evidence collectors, workspace transfer, and teardown policy.
- Knowledge plane: raw source preservation, LLM wiki patterns, and durable project memory.

## Implementation Status

As of 2026-04-09, the operational shape is:

- real control-plane APIs and operator UI for the Sheshnaag workflow
- signed run and bundle attestations
- real disclosure archive export
- reliable targeted integration coverage for run lifecycle, evidence, provenance, artifact review, and disclosure export
- execute-mode baseline collector support for:
  - `process_tree`
  - `package_inventory`
  - `file_diff`
  - `network_metadata`
  - `service_logs`
- an explicit osquery-capable image path for `osquery_snapshot`

Deferred from this architecture:

- Lima / VM-grade secure mode
- production-ready Tracee/Falco/Tetragon/PCAP maturity
- broader team/workflow expansions beyond the current v1.0 workstation story

## Current Runtime Shape

### Control Plane

- FastAPI application in `app/main.py`
- Sheshnaag APIs under:
  - `/api/intel`
  - `/api/candidates`
  - `/api/recipes`
  - `/api/runs`
  - `/api/evidence`
  - `/api/artifacts`
  - `/api/provenance`
  - `/api/ledger`
  - `/api/disclosures`
- Existing CVE, tenant, SBOM, VEX, and graph services retained as contextual inputs

### Validation Plane

- `LabProvider` abstraction in `app/lab/interfaces.py`
- `docker_kali` provider in `app/lab/docker_kali_provider.py`
- provider plan includes:
  - version-pinned Kali image
  - dedicated osquery-capable image path for `osquery_snapshot`
  - read-only root filesystem
  - explicit capability drops
  - security opts
  - host workspace mount into the guest workdir for artifact transfer and file-diff collection
  - ephemeral workspace and teardown policy
  - network policy representation
- default collectors via `app/lab/collectors/registry.py` and `app/lab/collector_contract.py`
- defensive artifact generation in `app/lab/artifact_generator.py`
- manifest signing in `app/lab/attestation.py`

### Knowledge Plane

- canonical PRD in [PROJECT_SHESHNAAG_PRD.md](./PROJECT_SHESHNAAG_PRD.md)
- marketing narrative in the frontend
- intended raw-source plus LLM wiki pattern documented in [SHESHNAAG_KNOWLEDGE_SYSTEM.md](./SHESHNAAG_KNOWLEDGE_SYSTEM.md)
- MemPalace used for durable project memory and decision continuity

## Data Model

### Reused Foundations

- `CVE`
- `AffectedProduct`
- `RiskScore`
- `Tenant`
- `Asset`
- `SoftwareComponent`
- `VexStatement`

### New Sheshnaag Models

- `SourceFeed`
- `AdvisoryRecord`
- `PackageRecord`
- `ProductRecord`
- `VersionRange`
- `ExploitSignal`
- `ResearchCandidate`
- `LabTemplate`
- `LabRecipe`
- `RecipeRevision`
- `LabRun`
- `RunEvent`
- `EvidenceArtifact`
- `DetectionArtifact`
- `MitigationArtifact`
- `AttestationRecord`
- `DisclosureBundle`
- `AnalystIdentity`
- `WorkstationFingerprint`
- `ContributionLedgerEntry`
- `ReviewDecision`

## API Philosophy

- Read flows can target the seeded demo tenant.
- Write flows require a writable tenant.
- Candidate and run flows are deterministic and explainable.
- Evidence, artifacts, and bundles are provenance-linked by design.

## Near-Term Evolution

- deepen package/advisory normalization
- broaden telemetry maturity beyond the baseline collectors and `osquery_snapshot`
- add richer disclosure packaging and review workflows
- add future secure-mode VM provider without changing the public recipe/run contract
