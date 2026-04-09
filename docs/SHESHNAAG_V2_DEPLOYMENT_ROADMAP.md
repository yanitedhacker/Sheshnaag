# Sheshnaag v2 Deployment Roadmap

Last updated: 2026-04-09

## Purpose

This document tracks what remains after the v1.0 gap-fill pass as Project Sheshnaag moves from a credible workstation-native defensive research lab toward a deployment-ready v2 platform.

This is not a replacement for the PRD. The PRD remains the product vision. This roadmap is the delivery document for the next stage: making Sheshnaag safe, reliable, supportable, and scalable enough for real sustained usage beyond the current v1.0 workstation story.

## Current Baseline

Sheshnaag now has:

- a real control plane and operator UI
- tenant-scoped signed provenance and disclosure archive export
- a Docker-backed execute path for the baseline live collectors
- a dedicated osquery-capable image path for `osquery_snapshot`
- targeted unit and integration coverage for lifecycle, evidence, provenance, artifact review, and disclosure export
- repeatable smoke and rehearsal scripts, with Docker-backed steps that self-skip when Docker is unavailable

Sheshnaag does not yet have:

- VM-grade secure mode
- deployment-grade secrets, key, and image supply-chain management
- broader production-ready telemetry beyond the baseline collectors and osquery slice
- full operational packaging for always-on environments and team workflows

## v2 Goal

Deliver a deployment-ready Sheshnaag platform that can be operated safely and repeatably by a small research or AppSec team, with stronger isolation, richer evidence, better review and disclosure workflows, and a realistic path from local-first usage to managed deployment.

The target outcome for v2 is:

- safe enough to trust with real analyst workflows
- observable enough to diagnose runtime and pipeline failures
- reproducible enough to support review, reruns, and audits
- deployable enough to run outside a single developer laptop
- still clearly defensive-only

## What Is Left To Do

### 1. Secure Validation Plane

Priority: highest

Sheshnaag still needs a stronger execution boundary than the current Docker-first path.

Remaining work:

- build the Lima / VM-backed secure-mode provider
- preserve the existing recipe/run contract while adding VM lifecycle support
- add snapshot, revert, and baseline restore semantics
- define secure workspace sync and export flow between host and guest
- ensure guest teardown is auditable and deterministic
- define when Docker execute mode is allowed versus when secure mode is mandatory

v2 acceptance:

- a VM-backed run can be planned, started, monitored, stopped, torn down, and destroyed through the same public Sheshnaag run APIs
- snapshot and revert behavior is verifiable in tests and smoke workflows
- sensitive recipes can require secure mode by policy

### 2. Production-Grade Image And Tooling Supply Chain

Priority: highest

The osquery image path exists, but Sheshnaag still lacks a full image-management story suitable for deployment.

Remaining work:

- define canonical Sheshnaag lab images and versioning policy
- publish and verify pinned baseline and telemetry-capable images
- sign images or otherwise record trusted image provenance
- replace ad hoc image assumptions with an image catalog policy
- add CI or release automation for image build, scan, and publication
- define compatibility matrix for baseline, osquery, and future telemetry images

v2 acceptance:

- every supported image has a documented source, build path, digest, and verification story
- operator-facing templates resolve to trusted images only
- smoke and release workflows can verify image availability and expected tooling

### 3. Telemetry Expansion Beyond Baseline + osquery

Priority: high

Sheshnaag needs richer live evidence than the current baseline plus one advanced slice.

Remaining work:

- promote one eBPF/runtime event path to real support: Tracee, Falco, or Tetragon
- decide whether PCAP remains optional, privileged-only, or secure-mode-only
- define truthful capability and degradation semantics across all collectors
- unify evidence payload conventions so operator UX and provenance flows can treat collectors consistently
- add baseline-vs-post-run comparisons where collectors need pre-run capture

Recommended sequencing:

1. one runtime event collector
2. deeper network evidence
3. fuller correlation between process, file, and network events

v2 acceptance:

- at least one runtime event collector is real, reproducible, and covered by execute or secure-mode smoke
- collector failure states remain explicit and never masquerade as successful evidence

### 4. Artifact Quality And Review Workflow

Priority: high

Artifact generation is working, but the current output is still early-stage.

Remaining work:

- improve artifact generation so rules and mitigations are grounded in stronger evidence patterns
- add richer review states, correction history, and supersession handling
- separate draft, approved, rejected, and deprecated artifact views in the UI
- add operator-facing rationale capture for approval and rejection
- add artifact quality metrics and tuning feedback loops

v2 acceptance:

- artifact outputs are evidence-backed enough for internal reuse
- review history is complete and visible in the operator workflow
- updated artifacts can supersede earlier ones without losing lineage

### 5. Disclosure And Reporting Hardening

Priority: high

Bundle export is real, but deployment-grade reporting still needs work.

Remaining work:

- improve report structure for vendor, bug bounty, and internal remediation use cases
- add richer redaction workflow and export safety controls
- define attachment policy for logs, PCAP, screenshots, and raw evidence
- support better reproduction steps, impact summaries, and fix guidance
- add stronger signing, verification UX, and export audit trail

v2 acceptance:

- exported bundles are suitable for real review and submission workflows
- sensitive evidence handling is explicit and operator-auditable
- disclosure templates differ by bundle type in meaningful ways

### 6. Candidate And Applicability Depth

Priority: medium-high

The candidate pipeline exists, but deployment-grade prioritization still needs deeper signal quality.

Remaining work:

- improve OSV and GitHub Advisory normalization
- deepen vendor advisory and patch-note mapping
- improve product/package/environment applicability
- enrich SBOM and VEX use in candidate scoring and artifact output
- support repeatable affected-versus-fixed comparison across versions

v2 acceptance:

- candidate ranking is more trustworthy for real analyst triage
- applicability reasoning is visible and auditable
- SBOM/VEX inputs meaningfully influence downstream workflows

### 7. Team Workflow And Multi-User Operations

Priority: medium-high

Sheshnaag is still strongest as a single-operator system.

Remaining work:

- add stronger assignment, reassignment, and queue ownership flows
- add correction history and contribution weighting in the ledger
- improve reviewer workflow across runs, artifacts, and disclosures
- add team-grade dashboards for throughput, stale work, and approval state
- define tenant and role policy for shared deployments

v2 acceptance:

- multiple analysts and reviewers can use the same deployment without ambiguous ownership
- contribution and review lineage remain attributable end to end

### 8. Deployment Packaging And Operations

Priority: highest

Sheshnaag still needs an actual deployment story rather than a development-only runtime shape.

Remaining work:

- define supported deployment topology: local, single-host lab, or small-team server
- externalize and harden secrets, signing-key storage, and environment config
- add deployment docs and environment-specific runbooks
- add health, readiness, and operational dashboards for deployed services
- harden database migration and backup/restore workflows
- define artifact, export, and evidence retention policy

v2 acceptance:

- a supported deployment can be brought up from clean infrastructure with documented steps
- recovery, backup, and upgrade workflows are tested
- operators can distinguish platform failure from lab-run failure quickly

### 9. Release Engineering And CI

Priority: high

The rehearsal path is much better, but v2 needs stronger automation.

Remaining work:

- split CI into fast, integration, and Docker-backed smoke stages
- add optional secure-mode test lanes when the VM provider lands
- add image build and verification jobs
- make release rehearsal suitable for pre-release automation
- record environment and capability metadata for smoke runs

v2 acceptance:

- every release candidate has a reproducible verification record
- failures point clearly to unit, integration, image, or runtime-execution regressions

### 10. Documentation And Operator Readiness

Priority: medium

The docs are now aligned, but v2 will need operator-grade documentation.

Remaining work:

- add deployment guides, operator playbooks, and troubleshooting docs
- document execute-mode versus secure-mode policy
- document supported images and telemetry profiles
- add evidence interpretation notes for the major collectors
- maintain a current “shipped vs deferred” status section in the core docs

v2 acceptance:

- a new engineer or operator can deploy, run, troubleshoot, and review Sheshnaag without reading the entire codebase

## Proposed Delivery Order

### Phase 1: Deployment Foundation

- deployment topology
- secrets and key management
- image catalog and image build pipeline
- CI and release verification hardening

### Phase 2: Secure Validation

- Lima / VM provider
- secure-mode policy
- snapshot and revert workflow

### Phase 3: Evidence Depth

- runtime event collector promotion
- network evidence deepening
- stronger baseline and diff semantics

### Phase 4: Review And Reporting

- artifact quality improvements
- disclosure/reporting improvements
- richer review workflow

### Phase 5: Team And Analytics

- multi-user workflow hardening
- ledger and contribution improvements
- team dashboards and operational analytics

## v2 Exit Criteria

Sheshnaag should not be called “v2-ready” until all of the following are true:

- deployed environments are documented and reproducible
- secure-mode validation exists and is policy-enforceable
- image provenance and signing-key handling are deployment-grade
- at least one advanced runtime telemetry path beyond osquery is real and supported
- disclosure output is suitable for real review/submission workflows
- multi-user review and contribution flows are reliable
- CI and release verification cover the real execution paths, not just simulated paths

## Explicitly Deferred Beyond v2

These items should stay out of scope unless priorities change:

- offensive execution tooling
- target discovery against third-party infrastructure
- exploit-chain automation
- generalized cloud detonation infrastructure
- large-scale SOC analytics unrelated to the Sheshnaag research workflow

## Recommended First v2 Tickets

- define the supported deployment topology and write the deployment assumptions doc
- design the Lima provider contract in enough detail to implement without changing public Sheshnaag APIs
- build the Sheshnaag image catalog and release pipeline for baseline and osquery-capable images
- choose one runtime event telemetry path for promotion and write its acceptance contract
- design deployment-grade signing-key storage and rotation behavior
