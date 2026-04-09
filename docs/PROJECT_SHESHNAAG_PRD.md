# Project Sheshnaag PRD

Version: 0.1  
Status: Draft  
Last updated: 2026-04-08

## Implementation Status Overlay

This PRD remains the product vision, not a statement that every capability below is already shipped.

Current shipped / working areas as of 2026-04-09:

- Sheshnaag control-plane APIs and operator UI for intel, candidates, recipes, runs, evidence, artifacts, provenance, ledger, and disclosures
- signed run and bundle attestations
- real disclosure archive export
- constrained Docker-backed execute mode for the baseline live collectors
- explicit osquery-capable image support for `osquery_snapshot`

Still deferred relative to the full PRD:

- Lima / VM-grade secure mode
- broader telemetry maturity across the full runtime-observability stack
- later roadmap/team-scale workflow expansions beyond the current v1.0 workstation story

Read the rest of this document as the target product and design intent. Use `README.md` and `docs/PROJECT_SHESHNAAG_ARCHITECTURE.md` as the current operational truth.

## 1. Executive Summary

Project Sheshnaag is a local-first defensive vulnerability research lab for enterprise software CVEs. It ingests live vulnerability intelligence, identifies research-worthy enterprise software issues, provisions isolated Linux validation environments, captures evidence safely, generates defensive detections and mitigations, and preserves signed provenance plus an analyst credit ledger.

Sheshnaag is not a general bug bounty scanner, phishing lab, or offensive exploitation platform. It is a controlled validation and defanging system for defensive research teams.

Core outcome:

- turn a CVE into a validated research candidate
- turn a candidate into a disposable lab recipe
- turn a lab run into evidence, detections, mitigations, and signed reporting artifacts
- turn analyst work into chain-of-custody records and reusable credits

## 2. Product Vision

### Vision Statement

Build the best workstation-native platform for defensive validation of enterprise software CVEs, where analysts can safely reproduce vulnerability conditions, observe system behavior, generate useful defensive outputs, and package the results as high-quality internal or external research deliverables.

### Product Tagline

Live CVE intelligence to isolated validation, defensive artifacts, and signed research evidence.

### Why This Product Should Exist

Most vulnerability dashboards stop at prioritization. Most sandbox tools focus on suspicious files, malware detonation, or generic runtime monitoring. Most bug bounty workflows are built around manual reporting after the fact.

Sheshnaag fills a gap:

- ingest CVE intelligence continuously
- focus on enterprise software and package-driven vulnerabilities
- make validation reproducible in local, controlled, Linux-backed environments
- produce defensive outputs, not offensive tooling
- package results into trustworthy bounty-ready or audit-ready evidence bundles

## 3. Product Goals

### Primary Goals

- continuously ingest and normalize enterprise software vulnerability intelligence
- identify research candidates worth analyst time
- launch isolated Linux validation environments from reproducible recipes
- collect high-value runtime and network evidence during validation
- generate defensive outputs such as detection logic, mitigation guidance, and VEX suggestions
- preserve end-to-end provenance and analyst accountability
- support external disclosure, bug bounty, or research bounty workflows with structured report bundles

### Secondary Goals

- provide a high-credibility portfolio-quality system that demonstrates depth in AI, security engineering, runtime telemetry, systems design, and product thinking
- create reusable lab recipes and evidence bundles that compound over time
- enable team-level governance, review, and contribution tracking

### Non-Goals

- phishing or social engineering workflows
- credential harvesting simulation
- exploit weaponization
- exploit reliability tuning
- autonomous target scanning of third-party infrastructure
- red-team style campaign orchestration
- malware distribution or execution outside tightly controlled lab boundaries

## 4. Safety and Use Boundaries

Sheshnaag must remain clearly non-operational and defensive.

Allowed:

- controlled validation of vulnerability conditions in isolated labs
- replaying safe, curated validation harnesses
- collecting telemetry and generating detections
- packaging responsible disclosure evidence
- producing mitigations, rules, and environment-specific recommendations

Not allowed:

- one-click exploit execution against public or customer infrastructure
- exploit chain generation intended for compromise operations
- automated target discovery against third-party assets
- public release of runnable weaponized content

Mandatory controls:

- isolated local Linux validation environments only
- current v0/v1 path uses constrained Kali-on-Docker with ephemeral teardown; future secure mode should add VM snapshot and revert semantics
- no host credential sharing
- default-deny egress with explicit allowlists
- signed analyst acknowledgement for sensitive runs
- audit trail for all lab actions

## 5. Target Users

### Primary Persona: Defensive Research Analyst

The primary user is an enterprise software vulnerability researcher who wants to validate whether a CVE matters, understand the behavior safely, and convert that work into detections, mitigations, and formal reporting artifacts.

Needs:

- fast candidate triage
- reproducible local labs
- structured evidence collection
- artifact generation
- chain of custody
- credit for authored work

### Secondary Persona: AppSec or Product Security Engineer

This user needs defensible proof, fix guidance, and environment-aware impact summaries for internal remediation or vendor disclosure.

Needs:

- clear reproduction notes
- fix and mitigation recommendations
- patch applicability
- version and environment mapping
- signed evidence bundles

### Tertiary Persona: Research Lead

This user needs research throughput, auditability, and contribution visibility.

Needs:

- assignment queues
- review workflow
- artifact quality metrics
- analyst scorecards
- bounty or reporting conversion metrics

## 6. Jobs To Be Done

- When a new enterprise software CVE drops, help me decide whether it is worth lab time.
- When I choose to validate a CVE, create a safe, reproducible Linux environment for that work.
- When I run validation, capture the most useful evidence automatically.
- When the run finishes, generate defensive artifacts I can use immediately.
- When I need to disclose or submit a report, package the result into a high-quality reproducible bundle.
- When my team reviews the work, preserve chain of custody and attribute the contribution correctly.

## 7. Product Principles

- Evidence first: every claim ties back to captured observations, cited advisories, or reproducible environment state.
- Local by default: the primary control plane and analyst workflow should work on a workstation without requiring a cloud sandbox.
- Isolation over convenience: use stronger isolation even when it costs some speed.
- Reproducibility over novelty: a rerunnable recipe is more valuable than an impressive one-off run.
- Defensive outputs only: every pipeline stage should bias toward mitigations and detections.
- Signed provenance everywhere: if it cannot be attributed and verified, it is incomplete.

## 8. Market Positioning

### What Sheshnaag Is

- a defensive vulnerability research lab
- a CVE-to-validation workflow engine
- a provenance-aware analyst workbench
- a packaging layer for responsible disclosure and defensive bounty submissions

### What Sheshnaag Is Not

- a commodity vulnerability dashboard
- a generic malware sandbox
- a crowdsourced bug bounty platform
- a penetration testing as a service vendor

### Differentiators

- enterprise software CVE focus, not generic web bug hunting
- local workstation control plane with Linux validation guests
- integrated candidate scoring plus lab orchestration
- first-class signed provenance and analyst credit ledger
- conversion of research into defensive artifacts and submission-ready evidence packs

## 9. Core Use Cases

### Use Case A: Internal Defensive Research

An analyst ingests a fresh CVE, evaluates relevance, launches a recipe, observes behavior, and publishes detections and mitigations for internal use.

### Use Case B: Responsible Vendor Disclosure

An analyst validates a vulnerability affecting an enterprise product or package and exports a complete, reproducible report bundle suitable for vendor reporting.

### Use Case C: Bug Bounty or Research Bounty Submission

An analyst validates an issue within scope of a public or private bounty program and uses the Sheshnaag evidence bundle to speed up a quality submission.

### Use Case D: Repeatable Variant Analysis

A team reruns an existing recipe against multiple versions or distro variants to confirm fixed versus affected status and generate VEX-style output.

## 10. Functional Requirements

### 10.1 Intel Ingestion

Sheshnaag must ingest and normalize:

- CVE data from NVD
- exploitation context from CISA KEV
- exploit probability signals from EPSS
- package and ecosystem vulnerability data from OSV
- package and advisory context from GitHub Advisory Database
- vendor advisories and patch notes when parsable
- SBOM and VEX documents from local or tenant data

The system must preserve source provenance for every field and update history for every material change.

### 10.2 Candidate Scoring

Sheshnaag must rank research candidates using:

- KEV inclusion
- EPSS score
- environment applicability
- package or product matching confidence
- Linux reproducibility confidence
- patch availability
- attack surface characteristics
- ease of observation in lab

The score must be explainable and not hidden behind opaque model logic.

### 10.3 Lab Recipes

Every candidate that enters validation must produce or attach to a `LabRecipe` with:

- target OS and distro
- target software and versions
- package source or image source
- configuration steps
- network policy
- ingress or sample requirements
- evidence collectors
- timeout and revert policy
- known-safe validation path

### 10.4 Validation Runs

Each lab run must store:

- analyst identity
- host workstation fingerprint
- guest template hash
- package versions
- recipe version
- start and end timestamps
- network and collector configuration
- run transcript
- evidence list
- review status

### 10.5 Evidence Collection

Collectors should support:

- process execution trees
- package inventory before and after
- file and path changes
- network connections
- DNS requests
- HTTP metadata where legal and applicable
- syscall and runtime events
- service logs
- PCAP
- container or VM metadata

### 10.6 Defensive Artifact Generation

Generate:

- Sigma rules
- Falco or eBPF-based runtime detections
- Suricata candidates where network patterns are meaningful
- YARA candidates for extracted artifacts or binaries when meaningful
- mitigation checklists
- patch and workaround summaries
- OpenVEX-style suggestion outputs
- CAB-ready and vendor-ready report bundles

### 10.7 Provenance and Ledger

Every meaningful output must be attributable to:

- analyst identity
- device identity
- recipe version
- run ID
- evidence set
- review chain

The platform must preserve:

- chain of custody
- authorship history
- contribution scores
- reuse lineage

## 11. Non-Functional Requirements

- must support macOS host as primary analyst workstation
- must use Linux guests for validation
- must tolerate partially offline workflows after feed sync
- must support reproducible reruns from immutable recipe versions
- must support exportable evidence bundles
- must provide low-noise telemetry defaults
- must avoid requiring cloud-only control plane features for core flows

## 12. Technical Architecture

### 12.1 Control Plane

Runs on the analyst workstation and owns:

- UI
- ingestion scheduler
- scoring engine
- recipe engine
- run orchestrator
- provenance service
- report exporter

### 12.2 Validation Plane

Runs in Linux guests and owns:

- target software installation
- validation harness execution
- collectors and telemetry
- evidence packaging
- run teardown and revert

### 12.3 Data Plane

Stores:

- normalized advisories
- recipes
- run metadata
- evidence metadata
- generated artifacts
- analyst identities
- attestation records
- contribution ledger

### 12.4 Recommended Local Host Strategy

For the current first release on macOS hosts:

- use a constrained Kali-on-Docker validation path as the first provider
- preserve a provider abstraction so a future Lima-backed secure mode can replace or supplement the Docker path
- treat Lima plus VM-backed snapshot/revert as the next isolation upgrade rather than the first implementation milestone
- treat Firecracker as a future Linux-host detonation primitive, not the default Mac path

### 12.5 Recommended Telemetry Stack

- Falco for curated runtime detections
- Tetragon for rich eBPF observability and enforcement-style policies
- Tracee for event capture, rule authoring flexibility, and output routing
- osquery for structured host-state and package/file/process queries
- PCAP and structured network metadata

### 12.6 Why These Tools Fit

- Tetragon is useful when Sheshnaag needs low-overhead kernel-level observability over process, file, and network activity.
- Tracee is useful when Sheshnaag needs flexible event pipelines, signature logic, and artifact-aware runtime observation.
- osquery is useful when Sheshnaag needs repeatable host-state snapshots and SQL-queryable evidence.

## 13. Data Model

### Core Entities

- `SourceFeed`
- `AdvisoryRecord`
- `CVERecord`
- `PackageRecord`
- `ProductRecord`
- `VersionRange`
- `ExploitSignal`
- `EnvironmentProfile`
- `ResearchCandidate`
- `LabTemplate`
- `LabRecipe`
- `RecipeRevision`
- `LabRun`
- `RunEvent`
- `EvidenceArtifact`
- `DetectionArtifact`
- `MitigationArtifact`
- `DisclosureBundle`
- `AttestationRecord`
- `AnalystIdentity`
- `WorkstationFingerprint`
- `ContributionLedgerEntry`
- `ReviewDecision`

### Key Relationships

- One `CVERecord` can have many `AdvisoryRecord`s.
- One `ResearchCandidate` references one `CVERecord` plus one or more environment and package matches.
- One `LabRecipe` can be revised many times.
- One `LabRun` executes exactly one `RecipeRevision`.
- One `LabRun` produces many `EvidenceArtifact`s and zero or more `DetectionArtifact`s.
- One `DisclosureBundle` references one or more `LabRun`s and selected evidence.
- One `ContributionLedgerEntry` references an analyst, an object type, and a scoring event.

## 14. UX and Surface Map

### 14.1 Intel Dashboard

Shows:

- feed freshness
- new CVEs
- candidate score deltas
- KEV and EPSS changes
- package ecosystem hotspots

### 14.2 Candidate Queue

Shows:

- candidate ranking
- explainable score factors
- package and version matches
- target environment fit
- lab readiness confidence
- patch and VEX state

Actions:

- create recipe
- assign analyst
- defer
- reject
- merge duplicate candidates

### 14.3 Recipe Builder

Shows:

- target distro
- package source
- service topology
- collector selection
- timeout
- egress policy
- revert policy

Actions:

- dry run
- save draft
- sign and approve
- launch

### 14.4 Run Console

Shows:

- guest status
- execution timeline
- live telemetry
- collector health
- policy violations
- captured artifacts

### 14.5 Evidence Explorer

Shows:

- process tree
- file diff
- package diff
- network graph
- osquery snapshots
- telemetry findings

### 14.6 Artifact Forge

Shows:

- generated Sigma, Falco, Suricata, YARA candidates
- mitigation text
- package pinning options
- review controls

### 14.7 Provenance Center

Shows:

- run manifest
- attestation records
- hashes
- signatures
- review history
- export history

### 14.8 Analyst Ledger

Shows:

- authored recipes
- accepted runs
- generated artifacts
- disclosures submitted
- bounty conversions
- peer review contributions

## 15. Roadmap Overview

This roadmap is intentionally versioned like a product delivery plan rather than a vague theme list.

### Version Naming

- `v0.x` = foundation and early usable product
- `v1.x` = credible research lab
- `v2.x` = team-grade research platform

## 16. Detailed Versioned Roadmap

### v0.1: Project Sheshnaag Reframe

Goal:

- keep product, repo, and operator-facing language consistently aligned to Project Sheshnaag
- establish the defensive vulnerability research lab identity

Deliverables:

- updated README and product narrative
- PRD and architecture docs
- renamed frontend labels
- clear safety policy page
- terminology migration in code and UI where feasible

Development steps:

1. Add PRD and supporting docs.
2. Update README positioning and roadmap.
3. Update frontend branding and product copy.
4. Add safety boundary statements in UI and docs.
5. Add backlog tags for `intel`, `candidate`, `recipe`, `run`, `artifact`, `attestation`, `ledger`.

Exit criteria:

- the repo clearly communicates the Sheshnaag vision
- internal terminology is aligned enough to build against

### v0.2: Live Intel Backbone

Goal:

- ingest live CVE and package-adjacent intelligence continuously

Deliverables:

- connectors for NVD, KEV, EPSS, OSV, GitHub advisories
- normalized vulnerability schema
- source citation and freshness tracking
- candidate scoring v1

Development steps:

1. Add source connector abstraction.
2. Implement source-specific parsers and schedulers.
3. Store raw source payloads with hashes.
4. Normalize CVE, package, product, version, advisory, and exploit-signal records.
5. Add scoring engine with explainable factors.
6. Add dashboard cards for feed freshness and candidate volume.

Exit criteria:

- feeds sync reliably
- duplicates collapse correctly
- every candidate score is explainable

### v0.3: Candidate Queue

Goal:

- replace generic risk ranking with validation-oriented candidate triage

Deliverables:

- candidate queue page
- filters by package, distro, KEV, EPSS, internet exposure, patch status
- “why this matters” explanations
- assignment and review states

Development steps:

1. Create candidate APIs and DTOs.
2. Add frontend queue and details page.
3. Add score explanation service.
4. Add analyst assignment.
5. Add defer, reject, and duplicate-merge actions.

Exit criteria:

- analysts can choose the next best research target in under five minutes

### v0.4: Linux Lab Foundation

Goal:

- provision disposable local Linux validation environments from the Mac host

Deliverables:

- constrained Docker-based Kali integration layer
- base templates for Ubuntu, Debian, Rocky
- teardown and ephemeral workspace reset support
- network policy defaults
- guest health and lifecycle tracking

Development steps:

1. Define lab provider abstraction.
2. Implement `docker_kali` provider first.
3. Add template catalog and metadata.
4. Add lifecycle APIs: plan, create, boot, stop, teardown, destroy.
5. Add network policy config.
6. Add host-to-guest artifact transfer with checksums.

Exit criteria:

- a disposable guest can be created, instrumented, and reverted repeatedly

### v0.5: Recipe System

Goal:

- make validation reproducible and reviewable

Deliverables:

- recipe schema
- recipe editor
- versioned recipe revisions
- safe-run policy gates

Development steps:

1. Define recipe DSL or JSON schema.
2. Add recipe revision model.
3. Build draft-save-launch UX.
4. Add approval and sign-off requirement for risky runs.
5. Add dry-run validation before launch.

Exit criteria:

- every validation run is tied to a versioned recipe revision

### v0.6: Evidence Pipeline

Goal:

- capture high-value telemetry by default

Deliverables:

- process trees
- file changes
- package state diffs
- network connection logs
- service logs
- basic PCAP capture
- osquery snapshots

Development steps:

1. Add collector registry.
2. Integrate osquery in guests for snapshot queries.
3. Add file diff collector.
4. Add network metadata collector.
5. Add evidence storage and indexing.
6. Add timeline view.

Exit criteria:

- runs produce enough evidence to support or reject claims confidently

### v0.7: Runtime Security Telemetry

Goal:

- capture defensive-relevant kernel and runtime events

Deliverables:

- Falco integration
- Tetragon integration
- Tracee integration
- event routing into evidence explorer

Development steps:

1. Start with one tool as default and support others as optional collectors.
2. Define normalized event envelope across Falco, Tetragon, and Tracee.
3. Add event-to-finding translation.
4. Add saved policies for enterprise software validation patterns.
5. Add collector-specific health and overhead telemetry.

Exit criteria:

- Sheshnaag can observe privilege changes, suspicious execution patterns, fileless activity indicators, and network egress behavior in a structured way

### v0.8: Artifact Forge v1

Goal:

- generate immediately useful defensive outputs

Deliverables:

- Sigma templates
- Falco rules
- Suricata candidates
- YARA candidates where applicable
- mitigation checklist generator

Development steps:

1. Define artifact schema and provenance fields.
2. Build rule-generation templates from evidence patterns.
3. Add review workflow and approval states.
4. Add export formats and bundle packaging.
5. Add false-positive feedback capture.

Exit criteria:

- a successful run can produce at least one reviewed defensive artifact

### v0.9: Provenance and Ledger v1

Goal:

- make every run defensible and attributable

Deliverables:

- analyst identity model
- workstation fingerprint model
- signed run manifests
- basic contribution ledger

Development steps:

1. Define attestation payload format.
2. Add hashing and signing pipeline.
3. Record recipe, guest, artifact, and evidence hashes.
4. Add ledger scoring rules.
5. Add provenance center UI.

Exit criteria:

- any exported bundle can be traced back to analyst, recipe, evidence, and review state

### v1.0: First Credible Release

Goal:

- ship the first version that is truly defensible and demoable

Release content:

- live ingestion
- candidate queue
- Linux lab provisioning
- versioned recipes
- evidence explorer
- runtime telemetry
- artifact forge
- provenance center
- analyst ledger

Success criteria:

- analysts can go from new CVE to signed evidence bundle on one workstation
- the product narrative is consistent and convincing

### v1.1: SBOM and VEX Deepening

Goal:

- make Sheshnaag environment-aware rather than advisory-only

Deliverables:

- richer SBOM import
- package-to-service mapping
- OpenVEX suggestion outputs
- fixed vs affected vs not-affected classification workflow

Development steps:

1. Improve package matching and version normalization.
2. Add service dependency graph overlay.
3. Add VEX authoring suggestions.
4. Add confidence scoring for applicability.

### v1.2: Disclosure and Bounty Bundles

Goal:

- convert validated research into high-quality submission-ready packages

Deliverables:

- vendor disclosure template
- bug bounty report template
- research bounty report template
- evidence redaction tools
- reproducibility appendix generator

Development steps:

1. Create bundle formats by destination type.
2. Add evidence selection and redaction workflow.
3. Add structured reproduction steps generator.
4. Add “proof package” export with signed manifest.

Exit criteria:

- an analyst can export a complete, actionable report package in minutes

### v1.3: Review and Team Workflow

Goal:

- support repeatable team operations

Deliverables:

- peer review queue
- artifact approval workflow
- dispute and correction history
- credit sharing and contribution weighting

### v1.4: Differential Validation

Goal:

- compare affected and fixed versions across environments

Deliverables:

- paired-run comparison
- before/after patch evidence
- regression support
- VEX confidence improvements

### v2.0: Team-Grade Defensive Research Platform

Goal:

- support multiple analysts, reusable recipe libraries, and monetizable reporting workflows

Deliverables:

- recipe marketplace inside the organization
- reusable evidence patterns
- cross-run clustering
- advanced policy libraries
- richer ledger analytics
- export APIs for partner and platform workflows

## 17. Monetization Strategy

Sheshnaag should be monetizable without crossing into exploit brokerage or ethically dubious markets.

### 17.1 Core Product Monetization

#### A. Enterprise License

Sell Sheshnaag as a local-first or hybrid defensive research platform to:

- internal AppSec teams
- product security teams
- PSIRTs
- MDR and detection engineering teams
- vendors with complex enterprise software portfolios

Packaging:

- single analyst license
- team license
- enterprise site license

#### B. Managed Research Workspace

Offer Sheshnaag as part software, part managed service:

- host deployment support
- curated templates
- telemetry policy packs
- report QA
- monthly validation retainer

#### C. Evidence and Compliance Exports

Charge for:

- audit-ready provenance packs
- signed run attestations
- compliance evidence exports
- review and approval workflows

This aligns with the broader PTaaS and proof-of-work reporting motion seen in market players such as Synack, but Sheshnaag stays focused on defensive CVE validation rather than broad offensive testing.

### 17.2 Bounty and Research Monetization

#### A. Bug Bounty Submission Assistant

Sheshnaag can package work into submission-quality bundles for platforms and vendor programs.

This is commercially useful because:

- Bugcrowd explicitly expects detailed descriptions, impact, reproduction steps, and proof of concept in reports.
- Apple explicitly requires complete and actionable reports with reliable reproduction or proof of concept.
- Vendor programs often reward only the first complete actionable report.

Inference:

Sheshnaag can help analysts win more rewards by raising report quality and reproducibility, not by increasing unsafe behavior.

Potential product model:

- per-submission export credits
- premium templates for specific bounty ecosystems
- disclosure quality scoring
- report review marketplace

#### B. Research Bounty Programs

Sheshnaag can support sponsor-funded defensive research campaigns such as:

- “validate this high-priority CVE across these distros”
- “produce Suricata and Sigma coverage for this advisory set”
- “confirm fixed vs affected state for these package versions”

Possible monetization models:

- sponsor-funded challenge pools
- fixed-fee validation tasks
- per-accepted-artifact payouts
- leaderboard-backed internal research sprints

This is safer than classic public bounty design because scope is constrained to defensive validation objectives.

#### C. Vendor and OSS Maintainer Packs

Offer a `Disclosure Bundle Pro` flow for:

- software vendors
- package maintainers
- enterprise product teams

The bundle should include:

- affected versions
- reproducible environment data
- validation conditions
- logs and evidence
- mitigations and recommended fix areas
- signed manifest

#### D. Internal Credit Ledger as Economic Layer

For companies and consulting teams, the ledger can support:

- analyst performance reviews
- internal bonuses
- bounty split accounting
- partner revenue sharing
- recipe reuse royalties or attribution

### 17.3 What Not To Monetize

- sale of unpatched weaponized exploit content
- brokering zero-days to offensive buyers
- public release of turnkey exploit bundles
- “pay per exploit” research marketplaces

Those paths would undermine the product, increase risk, and break the defensive positioning.

## 18. Bounty Workflow Opportunities

### Why Sheshnaag Can Help With Bounties

Current bounty programs reward:

- quality of reproduction
- clarity of impact
- speed of triage
- completeness of evidence
- discipline around disclosure

Sheshnaag can improve all five without changing the ethical boundary.

### Best-Fit Bounty Targets

- vendor programs for enterprise software products
- package ecosystem bug bounty targets
- managed disclosure programs
- internal private bounty programs for enterprises

### Less Suitable Targets

- social engineering programs
- consumer phishing reports
- broad browser or mobile exploit-chain categories unrelated to enterprise software validation

## 19. Metrics

### Product Metrics

- mean time from CVE ingest to candidate creation
- mean time from candidate approval to lab run
- mean time from run completion to artifact generation
- percentage of candidates with reproducible recipes
- percentage of runs producing exportable evidence bundles

### Research Quality Metrics

- reviewed artifact acceptance rate
- false-positive artifact rate
- rerun reproducibility rate
- evidence completeness score
- disclosure bundle acceptance rate

### Monetization Metrics

- number of exported vendor or bounty bundles
- accepted disclosure rate
- accepted bounty submission rate
- bounty dollars influenced by Sheshnaag-generated bundles
- paid team seats
- managed research revenue

## 20. Risks

### Product Risks

- local VM orchestration on macOS becomes brittle across host versions
- telemetry volume overwhelms the analyst
- evidence collection overhead distorts runs
- package and version normalization becomes messy across ecosystems

### Safety Risks

- accidental overreach into offensive behavior
- insufficient isolation between host and guest
- unsafe evidence exports
- misuse of bounty packaging for out-of-scope targets

### Business Risks

- bug bounty markets become noisier from AI-generated low-quality reports
- customers expect PTaaS breadth rather than CVE validation depth
- legal review requirements slow external disclosure workflows

## 21. Mitigations

- narrow the product around enterprise software CVEs
- bias toward deterministic recipes and curated validation harnesses
- make report quality and scope checks mandatory before external export
- add strong egress and host isolation defaults
- use signed provenance to differentiate from low-quality AI-generated outputs
- focus monetization on trust, reproducibility, and evidence quality

## 22. Suggested Repo Execution Plan

### Immediate Documentation Tasks

- add this PRD
- update README to Sheshnaag narrative
- add architecture doc
- add safety policy doc
- add roadmap tracking issue set

### Immediate Engineering Tasks

- refactor workbench concepts into candidate queue concepts
- add data models for recipes, runs, evidence, attestations, and ledger
- create provider abstraction for local Linux lab orchestration
- build a first evidence collector pipeline

### Immediate UX Tasks

- rename product and navigation
- add Candidate Queue page
- add Recipe Builder shell
- add Provenance Center shell
- add Analyst Ledger shell

## 23. External Research Notes

The roadmap and monetization ideas above are informed by current primary-source documentation and product materials, including:

- vulnerability intelligence and advisory sources
- macOS-hosted Linux VM tooling
- runtime telemetry tools
- disclosure and bounty platform workflows

Notable references:

- [Lima Docs](https://lima-vm.io/docs/)
- [Lima VM Types](https://lima-vm.io/docs/config/vmtype/)
- [Lima VZ Driver](https://lima-vm.io/docs/config/vmtype/vz/)
- [Lima Usage](https://lima-vm.io/docs/usage/)
- [Tetragon Overview](https://tetragon.io/docs/overview/)
- [Tetragon Observability Policies](https://tetragon.io/docs/policy-library/observability/)
- [Tracee Rules](https://aquasecurity.github.io/tracee/dev/docs/policies/rules/)
- [Tracee Output](https://aquasecurity.github.io/tracee/dev/docs/outputs/)
- [osquery SQL Introduction](https://osquery.readthedocs.io/en/stable/introduction/sql/)
- [osqueryd Introduction](https://osquery.readthedocs.io/en/stable/introduction/using-osqueryd/)
- [Bugcrowd Reporting a Bug](https://docs.bugcrowd.com/researchers/reporting-managing-submissions/reporting-a-bug/)
- [Bugcrowd Getting Rewarded](https://docs.bugcrowd.com/researchers/receiving-rewards/getting-rewarded/)
- [Bugcrowd Public Disclosure Policy](https://docs.bugcrowd.com/researchers/disclosure/disclosure/)
- [Bugcrowd VDP Essentials](https://docs.bugcrowd.com/customers/program-management/adding-new-engagements/adding-vulnerability-disclosure-program-essentials/)
- [HackerOne Bounty](https://www.hackerone.com/product/bounty)
- [HackerOne Bug Bounty Programs](https://www.hackerone.com/bug-bounty-programs)
- [Intigriti Platform](https://www.intigriti.com/)
- [Synack Platform](https://www.synack.com/platform/)
- [Synack PTaaS](https://www.synack.com/products/penetration-testing-as-a-service/)
- [Apple Security Bounty Guidelines](https://security.apple.com/bounty/guidelines/)
- [Apple Security Bounty Categories](https://security.apple.com/bounty/categories/)
- [Apple Security Bounty Target Flags](https://security.apple.com/bounty/target-flags/)
- [Microsoft Bounty Year in Review](https://msrc.microsoft.com/blog/2025/08/microsoft-bounty-program-year-in-review-17-million-in-rewards/)

## 24. Decision Summary

Project Sheshnaag should be built as:

- a defensive enterprise software CVE research lab
- a Mac-hosted, Linux-validated local-first platform
- an evidence and provenance system, not just a dashboard
- a tool that can help generate revenue through high-quality reporting, research services, and enterprise licensing

Its strongest moat is not “AI triage.”

Its moat is:

- reproducible defensive validation
- signed proof of work
- artifact generation
- analyst attribution
- bounty and disclosure packaging quality
