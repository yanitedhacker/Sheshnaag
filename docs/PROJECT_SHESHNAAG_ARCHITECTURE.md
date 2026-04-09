# Project Sheshnaag Architecture

## Summary

Project Sheshnaag is split into three planes:

- Control plane: FastAPI services for intel, candidate scoring, recipes, runs, provenance, and disclosure exports.
- Validation plane: constrained Kali-backed provider abstraction with evidence collectors and teardown policy.
- Knowledge plane: raw source preservation, LLM wiki patterns, and durable project memory.

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
  - read-only root filesystem
  - explicit capability drops
  - security opts
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
- replace synthetic evidence with richer local collectors
- add richer disclosure packaging and review workflows
- add future secure-mode VM provider without changing the public recipe/run contract
