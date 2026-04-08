# Sheshnaag Expansion Roadmap

## 1. Document Purpose

- This document converts the current Sheshnaag PRD gaps into an execution-ready delivery roadmap.
- This roadmap is intentionally written for a junior-heavy engineering team.
- This roadmap assumes a staff engineer or tech lead reviews design checkpoints, but most implementation is done by junior developers.
- This roadmap is designed so multiple developers can work in parallel with minimal merge conflicts.
- This roadmap covers all major gaps identified in the repo as of 2026-04-08.
- This roadmap is meant to be operational, not inspirational.
- This roadmap is not a product vision replacement.
- This roadmap is not a generic agile template.
- This roadmap is the implementation playbook for making Sheshnaag match and exceed its PRD.
- This roadmap targets the highest credible capacity of the project while preserving Sheshnaag's defensive-only posture.

## 2. Source Assumptions

- The source PRD is [`docs/PROJECT_SHESHNAAG_PRD.md`](/Users/archishmanpaul/Desktop/Sheshnaag/docs/PROJECT_SHESHNAAG_PRD.md).
- The current architecture reference is [`docs/PROJECT_SHESHNAAG_ARCHITECTURE.md`](/Users/archishmanpaul/Desktop/Sheshnaag/docs/PROJECT_SHESHNAAG_ARCHITECTURE.md).
- The current Sheshnaag backend entrypoint is [`app/main.py`](/Users/archishmanpaul/Desktop/Sheshnaag/app/main.py).
- The current Sheshnaag core service layer is [`app/services/sheshnaag_service.py`](/Users/archishmanpaul/Desktop/Sheshnaag/app/services/sheshnaag_service.py).
- The current lab provider is [`app/lab/docker_kali_provider.py`](/Users/archishmanpaul/Desktop/Sheshnaag/app/lab/docker_kali_provider.py).
- The current collectors are [`app/lab/collectors.py`](/Users/archishmanpaul/Desktop/Sheshnaag/app/lab/collectors.py).
- The current artifact generator is [`app/lab/artifact_generator.py`](/Users/archishmanpaul/Desktop/Sheshnaag/app/lab/artifact_generator.py).
- The current attestation helper is [`app/lab/attestation.py`](/Users/archishmanpaul/Desktop/Sheshnaag/app/lab/attestation.py).
- The current frontend route entry is [`frontend/src/App.tsx`](/Users/archishmanpaul/Desktop/Sheshnaag/frontend/src/App.tsx).
- The current frontend client wiring is [`frontend/src/api.ts`](/Users/archishmanpaul/Desktop/Sheshnaag/frontend/src/api.ts).

## 3. Current-State Summary

- Sheshnaag has a backend data model for candidates, recipes, runs, evidence, artifacts, provenance, disclosures, and ledger records.
- Sheshnaag has backend APIs for the core entities.
- Sheshnaag has a coherent service-level happy path for candidate -> recipe -> approval -> run -> evidence -> artifact -> provenance -> disclosure.
- Sheshnaag does not have a real validation execution engine yet.
- Sheshnaag does not have real evidence collectors yet.
- Sheshnaag does not have runtime telemetry integrations yet.
- Sheshnaag does not have real bundle packaging yet.
- Sheshnaag does not have strong signing yet.
- Sheshnaag does not have a real operator frontend yet.
- Sheshnaag still contains legacy CVE Threat Radar flows that are more mature than the new Sheshnaag flows.
- Sheshnaag needs a deliberate expansion plan so the team does not accidentally build features in the wrong order.

## 4. Program Goal

- Deliver a truly defensible Sheshnaag `v1.0` that supports the full local-first journey from CVE intake to signed evidence bundle on a single workstation.
- Deliver a mature `v1.1` and `v1.2` layer for SBOM, VEX, and disclosure-quality exports.
- Deliver a team-grade `v1.3`, `v1.4`, and `v2.0` expansion path without major rewrites.

## 5. Program Success Criteria

- Analysts can ingest fresh CVE intelligence without manual DB seeding.
- Analysts can filter and select candidates in a real candidate queue UI.
- Analysts can create, revise, approve, dry-run, launch, stop, and tear down recipes.
- Validation runs can execute inside constrained Linux guests with observable lifecycle events.
- Runs collect real telemetry and evidence artifacts instead of synthetic placeholders.
- Evidence can support defensible conclusions about affected versus not affected behavior.
- Artifact generation uses real evidence patterns and supports review states.
- Provenance can trace every major object to analyst, workstation, recipe revision, evidence set, and review chain.
- Disclosure bundles are exportable as actual files, not just DB rows.
- Team workflows support review, reassignment, correction history, and contribution weighting.
- The frontend exposes operator workflows instead of only marketing copy.
- The platform remains clearly defensive-only.

## 6. Planning Principles

- Build the narrowest credible vertical slices first.
- Never let frontend mock progress hide backend gaps.
- Never let backend route count be treated as product completeness.
- Prefer deterministic systems over vague AI-generated behavior.
- Every major milestone must end with a demoable workflow.
- Junior developers should own bounded slices with explicit file ownership.
- Every slice must include tests, docs, and failure mode handling.
- Every slice must include a rollback plan.
- Every slice must define what is out of scope.
- Every slice must define review checkpoints.

## 7. Delivery Model

- Delivery will run in parallel workstreams.
- Each workstream has a stable owner pod.
- Each pod has one lead reviewer.
- Each pod has its own file ownership rules.
- Cross-pod interfaces must be documented before coding starts.
- Pods may not block each other on unfinished UI.
- Pods may use mock data at the API boundary only when the interface contract is frozen.
- Pods may not invent new domain terms without architecture review.

## 8. Team Topology

- Pod A: Intel and normalization.
- Pod B: Candidate scoring and triage backend.
- Pod C: Lab provider and lifecycle orchestration.
- Pod D: Evidence collection and runtime telemetry.
- Pod E: Artifact forge and defensive outputs.
- Pod F: Provenance, ledger, review chain, and disclosures.
- Pod G: Frontend operator UX.
- Pod H: QA, test harnesses, platform safety, and release engineering.

## 9. Junior Developer Operating Rules

- No junior developer should change more than three major directories in one ticket.
- No junior developer should define a new persistent schema without review.
- No junior developer should merge a task that lacks an acceptance test.
- No junior developer should couple UI code to provisional backend payloads.
- No junior developer should add magic scoring constants without comments and tests.
- No junior developer should ship live lab execution without explicit safety review.
- No junior developer should expose host-sensitive file mounts by default.
- No junior developer should add telemetry tools without a resource budget note.

## 10. File Ownership Map

- Pod A owns `app/ingestion/*`.
- Pod A owns `app/services/intel_service.py`.
- Pod A owns Sheshnaag-related feed DTO changes in `app/models/*`.
- Pod B owns `app/services/sheshnaag_service.py` candidate logic.
- Pod B owns `app/api/routes/intel_routes.py`.
- Pod B owns `app/api/routes/candidate_routes.py`.
- Pod C owns `app/lab/interfaces.py`.
- Pod C owns `app/lab/docker_kali_provider.py`.
- Pod C owns future provider modules under `app/lab/*provider*.py`.
- Pod C owns run lifecycle pieces in `app/services/sheshnaag_service.py`.
- Pod D owns `app/lab/collectors.py`.
- Pod D owns collector plugin modules.
- Pod D owns telemetry normalization logic.
- Pod E owns `app/lab/artifact_generator.py`.
- Pod E owns artifact review API additions.
- Pod F owns `app/lab/attestation.py`.
- Pod F owns provenance, ledger, disclosure, and review APIs.
- Pod G owns `frontend/src/*`.
- Pod H owns `tests/*`, lab fixtures, smoke scripts, and CI documentation.

## 11. Branching Rules

- Use one branch per ticket.
- Prefix branches with `codex/`.
- Example format: `codex/ws3-candidate-filters`.
- Example format: `codex/ws6-osquery-snapshot-collector`.
- Each PR should touch one pod's owned files plus shared contract files.
- Shared contract files require explicit reviewer sign-off from each affected pod.

## 12. Definition of Done

- Code compiles.
- Tests pass locally.
- New behavior has unit tests.
- New behavior has at least one integration test if it crosses API boundaries.
- Docs are updated.
- Feature flags exist where rollout risk is high.
- Failure states are represented in payloads.
- Logs are actionable.
- Error messages are understandable by operators.
- The reviewer can demo the ticket in under five minutes.

## 13. Release Gates

- Gate 1: `v0.6` evidence pipeline is real enough to replace synthetic placeholders for core run types.
- Gate 2: `v0.8` artifact generation is evidence-backed and reviewable.
- Gate 3: `v0.9` provenance and ledger trace a run end-to-end.
- Gate 4: `v1.0` supports the full workstation story.
- Gate 5: `v1.1` adds SBOM and VEX-driven applicability depth.
- Gate 6: `v1.2` supports export-quality disclosure bundles.
- Gate 7: `v1.3` supports repeatable team workflows.
- Gate 8: `v1.4` supports differential validation.
- Gate 9: `v2.0` supports team-grade libraries and analytics.

## 14. High-Level Delivery Phases

- Phase 0: Program setup and backlog normalization.
- Phase 1: Intel backbone completion.
- Phase 2: Candidate queue completion.
- Phase 3: Real lab execution and lifecycle control.
- Phase 4: Evidence pipeline completion.
- Phase 5: Runtime telemetry integration.
- Phase 6: Artifact forge completion.
- Phase 7: Provenance, ledger, and disclosure completion.
- Phase 8: Full operator frontend.
- Phase 9: Team workflow, differential validation, and advanced platform maturity.

## 15. Dependency Rules

- Candidate UI depends on candidate API contract stability.
- Recipe builder UI depends on recipe schema freeze.
- Run console depends on lifecycle API expansion.
- Evidence explorer depends on evidence schema freeze.
- Artifact review UI depends on artifact state machine support.
- Provenance center depends on attestation payload format stability.
- Disclosure export UI depends on real bundle packaging.
- Differential validation depends on real rerunnable runs.

## 16. Parallelization Rules

- Pod A and Pod B can work in parallel once candidate DTOs are frozen.
- Pod C and Pod D can work in parallel once collector interface contracts are frozen.
- Pod E can start once evidence envelope fields are frozen.
- Pod F can start provenance format design before Pods C through E finish.
- Pod G can build shells once route maps and API contracts are frozen.
- Pod H starts on day one and never stops.

## 17. Minute Estimate Rules

- All task estimates below are hands-on implementation minutes.
- Do not confuse them with elapsed calendar time.
- Junior developers should add a 15 percent buffer to all estimates.
- Review time is listed separately when needed.
- QA time is listed separately when needed.
- Pairing time is listed separately when needed.
- If a task exceeds 480 minutes, split it before assigning it to a junior developer.

## 18. Program Timeline

- Week 0: Program setup and contract freeze.
- Week 1: Intel completion track starts.
- Week 2: Candidate queue and lifecycle APIs deepen.
- Week 3: Lab provider execution groundwork.
- Week 4: Evidence pipeline real collectors begin.
- Week 5: Frontend candidate and recipe surfaces begin.
- Week 6: Run console and lifecycle control begin.
- Week 7: Runtime telemetry proof of concept.
- Week 8: Artifact forge evidence mapping.
- Week 9: Provenance center and disclosure packaging.
- Week 10: Full integration hardening.
- Week 11: v1.0 dress rehearsal.
- Week 12: v1.0 release candidate.
- Week 13 through Week 16: SBOM, VEX, disclosure-quality expansion.
- Week 17 through Week 20: Team workflow and differential validation.
- Week 21 through Week 24: v2.0 foundations.

## 19. Master Milestone Map

- Milestone M0: Program alignment and team setup.
- Milestone M1: Live intel backbone completed.
- Milestone M2: Candidate queue backend and frontend completed.
- Milestone M3: Docker-based Linux lab execution completed.
- Milestone M4: Evidence pipeline upgraded from synthetic to real.
- Milestone M5: Runtime telemetry stack integrated.
- Milestone M6: Artifact forge upgraded to evidence-backed outputs.
- Milestone M7: Provenance, ledger, and review chain completed.
- Milestone M8: Disclosure bundles completed.
- Milestone M9: Operator frontend completed.
- Milestone M10: v1.0 integrated release.
- Milestone M11: SBOM and VEX deepening.
- Milestone M12: Team workflow and differential validation.
- Milestone M13: v2.0 platform foundations.

## 20. Workstream Index

- WS0: Program setup and engineering hygiene.
- WS1: Intel ingestion and normalization.
- WS2: Candidate scoring and triage backend.
- WS3: Candidate queue and operator UX.
- WS4: Lab provider, templates, and lifecycle control.
- WS5: Recipe system completion.
- WS6: Evidence pipeline completion.
- WS7: Runtime telemetry integration.
- WS8: Artifact forge completion.
- WS9: Provenance and ledger completion.
- WS10: Disclosure and export bundles.
- WS11: Full operator frontend.
- WS12: Testing, QA, and release engineering.
- WS13: Security hardening and safety controls.
- WS14: v1.1 and v1.2 expansion.
- WS15: v1.3, v1.4, and v2.0 expansion.

## 21. WS0 Overview

- Objective: make the team able to deliver the rest of the roadmap without chaos.
- Pod owner: Pod H.
- Supporting pods: all.
- Blocking risk: high.
- Parallelization impact: very high.
- Must finish by: end of Week 0.

### WS0 Deliverables

- backlog decomposition
- file ownership map
- API contract docs
- schema migration policy
- feature flag policy
- review checklist
- testing matrix
- release dashboard

### WS0 Ticket WS0-T1

- Title: Build the Sheshnaag expansion backlog board.
- Primary owner: junior project engineer.
- Reviewer: tech lead.
- Estimate: 180 minutes.
- Review estimate: 30 minutes.
- Files: `docs/sheshnaag_expansion.md`, issue tracker, project board.
- Dependencies: none.
- Implementation steps:
  - Read the PRD top to bottom.
  - Read the architecture doc top to bottom.
  - Read the current gap analysis summary.
  - Create milestone columns M0 through M13.
  - Create swimlanes per workstream WS0 through WS15.
  - Create labels for `backend`, `frontend`, `infra`, `telemetry`, `security`, `docs`, `qa`.
  - Create labels for `safe-to-parallelize`, `needs-contract-freeze`, `schema-change`, `high-risk`.
  - Create one issue per ticket in this roadmap.
  - Add explicit acceptance criteria to every issue.
  - Add dependency links between issues.
- Acceptance criteria:
  - Every roadmap ticket exists in the tracker.
  - Every ticket has a pod owner.
  - Every ticket has an estimate.
  - Every ticket has dependencies recorded.

### WS0 Ticket WS0-T2

- Title: Freeze file ownership and merge conflict rules.
- Primary owner: junior QA engineer.
- Reviewer: staff engineer.
- Estimate: 120 minutes.
- Review estimate: 20 minutes.
- Files: `docs/sheshnaag_expansion.md`, `CONTRIBUTING.md`.
- Dependencies: WS0-T1.
- Implementation steps:
  - Convert the ownership map in this document into `CONTRIBUTING.md`.
  - Add a rule for cross-pod shared files.
  - Add a reviewer escalation rule.
  - Add a rule for migration files.
  - Add a rule for frontend route ownership.
  - Add a rule for test fixture ownership.
  - Add examples of acceptable and unacceptable PR scope.
- Acceptance criteria:
  - Ownership rules are committed.
  - Every developer can answer which files they own.
  - The reviewer checklist references the ownership rules.

### WS0 Ticket WS0-T3

- Title: Define API contract versioning rules.
- Primary owner: junior backend engineer.
- Reviewer: tech lead.
- Estimate: 150 minutes.
- Review estimate: 30 minutes.
- Files: `docs/PROJECT_SHESHNAAG_ARCHITECTURE.md`, `docs/sheshnaag_expansion.md`.
- Dependencies: WS0-T1.
- Implementation steps:
  - List every Sheshnaag API route.
  - Group routes by entity.
  - Mark stable fields.
  - Mark provisional fields.
  - Define how breaking changes will be communicated.
  - Define how deprecated fields remain supported during transition.
  - Define how frontend mocks will follow the contracts.
- Acceptance criteria:
  - Contract stability levels are documented.
  - Shared pods acknowledge the rules.

### WS0 Ticket WS0-T4

- Title: Define migration and seed data policy.
- Primary owner: junior backend engineer.
- Reviewer: senior backend engineer.
- Estimate: 150 minutes.
- Review estimate: 30 minutes.
- Files: `app/migrations/*`, `scripts/init_db.py`, `README.md`.
- Dependencies: none.
- Implementation steps:
  - Document when `Base.metadata.create_all` is acceptable versus when migrations are required.
  - Define dev seed versus demo seed versus test seed boundaries.
  - Define fixture reset rules.
  - Define how to roll forward and roll back migrations.
  - Define naming conventions for migration files.
- Acceptance criteria:
  - Migration policy is documented.
  - Demo seed usage is separated from private-tenant testing guidance.

### WS0 Ticket WS0-T5

- Title: Create feature flag strategy.
- Primary owner: junior platform engineer.
- Reviewer: staff engineer.
- Estimate: 180 minutes.
- Review estimate: 30 minutes.
- Files: `app/core/config.py`, `README.md`, env docs.
- Dependencies: WS0-T3.
- Implementation steps:
  - Define flags for live run execution.
  - Define flags for osquery collector.
  - Define flags for PCAP capture.
  - Define flags for Tracee integration.
  - Define flags for Falco integration.
  - Define flags for Tetragon integration.
  - Define flags for disclosure export types.
  - Define flags for operator UI route exposure.
- Acceptance criteria:
  - All high-risk features have a planned flag.
  - Flags have env variable names.

### WS0 Ticket WS0-T6

- Title: Create release checklist template.
- Primary owner: junior release engineer.
- Reviewer: Pod H lead.
- Estimate: 120 minutes.
- Review estimate: 20 minutes.
- Files: `docs/sheshnaag_expansion.md`, `README.md`.
- Dependencies: WS0-T1.
- Implementation steps:
  - Define pre-release checklist.
  - Define smoke test checklist.
  - Define rollback checklist.
  - Define sign-off checklist.
  - Define evidence retention checklist for live-run features.
- Acceptance criteria:
  - The team has a reusable release checklist.

## 22. WS1 Overview

- Objective: complete the live intel backbone to match the PRD.
- Pod owner: Pod A.
- Supporting pods: Pod B, Pod H.
- Blocking risk: high.
- Parallelization impact: high.
- Must start by: Week 1.
- Must reach useful completion by: Week 4.

### WS1 Missing Capabilities

- OSV connector
- GitHub Advisory connector
- vendor advisory ingestion
- patch note ingestion
- source freshness linked to real syncs
- source provenance for normalized fields
- raw payload hashing for all sources
- update history tracking
- better exploit signal modeling

### WS1 Ticket WS1-T1

- Title: Refactor feed aggregator into source connector abstraction.
- Primary owner: junior backend engineer.
- Reviewer: Pod A lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: `app/ingestion/feed_aggregator.py`, `app/ingestion/__init__.py`.
- Dependencies: WS0-T3.
- Implementation steps:
  - Create a `FeedConnector` protocol or base class.
  - Move NVD-specific orchestration behind that interface.
  - Move Exploit-DB-specific orchestration behind that interface.
  - Define connector metadata methods for source name, cursor support, and freshness.
  - Make the aggregator iterate connectors rather than hard-coded clients.
  - Preserve current API behavior while refactoring.
  - Add unit tests for connector registration and invocation ordering.
- Acceptance criteria:
  - NVD and Exploit-DB are no longer hard-coded branches in the aggregator.
  - Adding a new feed requires adding a connector, not editing aggregator control flow.

### WS1 Ticket WS1-T2

- Title: Implement OSV connector.
- Primary owner: junior backend engineer.
- Reviewer: Pod A lead.
- Estimate: 360 minutes.
- Review estimate: 60 minutes.
- Files: `app/ingestion/osv_client.py`, `app/ingestion/feed_aggregator.py`, tests.
- Dependencies: WS1-T1.
- Implementation steps:
  - Create an OSV client module.
  - Define request models and response parsing helpers.
  - Normalize package ecosystem fields.
  - Preserve raw payloads.
  - Hash raw payloads.
  - Map OSV advisories to `AdvisoryRecord`, `PackageRecord`, and `VersionRange`.
  - Add source freshness updates.
  - Add retry and timeout behavior.
  - Add unit tests for parsing and persistence.
- Acceptance criteria:
  - OSV advisories can be synced into normalized entities.
  - Duplicate advisories do not create duplicate package rows.

### WS1 Ticket WS1-T3

- Title: Implement GitHub Advisory connector.
- Primary owner: junior backend engineer.
- Reviewer: Pod A lead.
- Estimate: 360 minutes.
- Review estimate: 60 minutes.
- Files: `app/ingestion/ghsa_client.py`, `app/ingestion/feed_aggregator.py`, tests.
- Dependencies: WS1-T1.
- Implementation steps:
  - Create a GitHub Advisory client module.
  - Normalize GHSA IDs.
  - Parse package ecosystems, versions, summary, references, and severity metadata.
  - Preserve raw payloads.
  - Hash raw payloads.
  - Link advisories to CVEs where possible.
  - Create or update `PackageRecord` rows.
  - Add test coverage for advisories with and without CVE mapping.
- Acceptance criteria:
  - GHSA data lands in the normalized schema.
  - Unmapped advisories remain queryable and provenance-linked.

### WS1 Ticket WS1-T4

- Title: Wire real KEV and EPSS ingestion instead of relying on demo-only seed data.
- Primary owner: junior backend engineer.
- Reviewer: Pod A lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: `app/services/intel_service.py`, new ingestion clients, tests.
- Dependencies: WS1-T1.
- Implementation steps:
  - Identify where KEV and EPSS are currently demo seeded.
  - Create clients or sync jobs for KEV and EPSS.
  - Persist latest snapshots plus historical update points.
  - Add source URLs and raw payload capture.
  - Update feed freshness records from actual syncs.
  - Preserve demo seed only as fallback fixture data.
  - Update candidate sync to use actual latest data first.
- Acceptance criteria:
  - Fresh KEV and EPSS data can be ingested without demo seeding.
  - Historical rows remain queryable.

### WS1 Ticket WS1-T5

- Title: Implement source freshness and update history correctly.
- Primary owner: junior backend engineer.
- Reviewer: senior backend engineer.
- Estimate: 240 minutes.
- Review estimate: 45 minutes.
- Files: `app/models/sheshnaag.py`, ingestion modules, tests.
- Dependencies: WS1-T1.
- Implementation steps:
  - Decide whether to extend `SourceFeed` or add a `SourceFeedRun` history table.
  - Record start time, end time, status, item count, and error summary per sync.
  - Update freshness on success only.
  - Preserve raw payload hash summaries.
  - Expose recent feed run history via API.
- Acceptance criteria:
  - Operators can see when each feed last ran and whether it succeeded.
  - Debugging a bad sync does not require log digging alone.

### WS1 Ticket WS1-T6

- Title: Add vendor advisory ingestion adapter framework.
- Primary owner: junior backend engineer.
- Reviewer: Pod A lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: `app/ingestion/vendor_advisory_client.py`, parser docs, tests.
- Dependencies: WS1-T1.
- Implementation steps:
  - Create a generic adapter structure for vendor advisories.
  - Support manual registration of parsers by vendor.
  - Define a common normalized payload shape.
  - Preserve source URL, published time, title, summary, and affected version hints.
  - Add one example adapter using static fixture data.
- Acceptance criteria:
  - The system can support vendor advisory parsers without rewriting ingestion control flow.

### WS1 Ticket WS1-T7

- Title: Add patch note ingestion support.
- Primary owner: junior backend engineer.
- Reviewer: Pod A lead.
- Estimate: 240 minutes.
- Review estimate: 45 minutes.
- Files: new ingestion module, tests.
- Dependencies: WS1-T6.
- Implementation steps:
  - Define what counts as a patch note document.
  - Normalize patch note metadata into advisories or knowledge documents.
  - Link patch notes to products, packages, and CVEs where possible.
  - Preserve provenance for partially parsed notes.
  - Add tests for incomplete mapping scenarios.
- Acceptance criteria:
  - Patch notes can be stored even when full mapping is not possible.

### WS1 Ticket WS1-T8

- Title: Expose Sheshnaag feed freshness in the intel overview and future dashboard widgets.
- Primary owner: junior backend engineer.
- Reviewer: Pod B lead.
- Estimate: 180 minutes.
- Review estimate: 30 minutes.
- Files: `app/services/sheshnaag_service.py`, `app/api/routes/intel_routes.py`, frontend contract docs.
- Dependencies: WS1-T5.
- Implementation steps:
  - Add per-feed freshness state to intel overview payload.
  - Include stale status thresholds.
  - Include last error snippets.
  - Include recent item count deltas.
  - Keep payload compact enough for dashboard cards.
- Acceptance criteria:
  - Frontend can render feed freshness cards without additional calls.

### WS1 Ticket WS1-T9

- Title: Build integration tests for live intel routes.
- Primary owner: junior QA engineer.
- Reviewer: Pod H lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: `tests/integration/*`.
- Dependencies: WS1-T2, WS1-T3, WS1-T4, WS1-T5.
- Implementation steps:
  - Add tests for `/api/intel/overview`.
  - Add tests for feed status surfaces.
  - Add tests that validate freshness fields.
  - Add tests that validate `planned`, `active`, `error`, and `stale` states.
  - Add tests for duplicate collapsing.
- Acceptance criteria:
  - The new intel backbone is verified by integration coverage.

## 23. WS2 Overview

- Objective: make candidate scoring and triage PRD-complete on the backend.
- Pod owner: Pod B.
- Supporting pods: Pod A, Pod H.
- Blocking risk: high.
- Parallelization impact: high.
- Must start by: Week 1.
- Must reach useful completion by: Week 5.

### WS2 Missing Capabilities

- richer candidate ranking
- better package and product applicability
- distro targeting
- patch and VEX state depth
- candidate actions beyond assign
- duplicate merge support
- reject and defer reasons
- explicit explainability richness
- real queue filtering support

### WS2 Ticket WS2-T1

- Title: Expand candidate scoring factors and make them explicit.
- Primary owner: junior backend engineer.
- Reviewer: Pod B lead.
- Estimate: 360 minutes.
- Review estimate: 60 minutes.
- Files: `app/services/sheshnaag_service.py`, tests.
- Dependencies: WS1-T2, WS1-T3, WS1-T4.
- Implementation steps:
  - Define factor structure for KEV, EPSS, environment applicability, package confidence, Linux reproducibility, patch availability, attack surface, and observability.
  - Replace implicit score math with named weights.
  - Comment why each factor exists.
  - Add tests for each factor contribution.
  - Add tests for score boundary transitions.
- Acceptance criteria:
  - Every score factor is visible and tested.
  - Weight changes are isolated in one place.

### WS2 Ticket WS2-T2

- Title: Add candidate status model with defer, reject, duplicate, and archived states.
- Primary owner: junior backend engineer.
- Reviewer: senior backend engineer.
- Estimate: 240 minutes.
- Review estimate: 45 minutes.
- Files: `app/models/sheshnaag.py`, `app/services/sheshnaag_service.py`, tests.
- Dependencies: WS0-T4.
- Implementation steps:
  - Extend candidate status options.
  - Add reason fields or transition event support.
  - Add timestamps for decision actions.
  - Add transition methods in the service layer.
  - Prevent invalid state changes.
- Acceptance criteria:
  - Candidates can be actively triaged, not only assigned.

### WS2 Ticket WS2-T3

- Title: Add candidate actions API surface for defer, reject, restore, and merge duplicate.
- Primary owner: junior backend engineer.
- Reviewer: Pod B lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: `app/api/routes/candidate_routes.py`, `app/services/sheshnaag_service.py`, tests.
- Dependencies: WS2-T2.
- Implementation steps:
  - Add request models per action.
  - Add one route per action or a generic transition route with strict validation.
  - Add merge-duplicate semantics.
  - Preserve an audit trail for actions.
  - Add unit and integration tests.
- Acceptance criteria:
  - All candidate queue PRD actions are API-supported.

### WS2 Ticket WS2-T4

- Title: Add candidate filters for package, distro, KEV, EPSS band, exposure, patch status, and assignment.
- Primary owner: junior backend engineer.
- Reviewer: Pod B lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: `app/api/routes/candidate_routes.py`, `app/services/sheshnaag_service.py`, tests.
- Dependencies: WS2-T1.
- Implementation steps:
  - Define filter parameters and validation.
  - Add query logic.
  - Add sorting controls.
  - Add pagination support if needed.
  - Add tests for each filter and combinations.
- Acceptance criteria:
  - Candidate queue filters align with the PRD.

### WS2 Ticket WS2-T5

- Title: Improve environment applicability using SBOM, VEX, and tenant asset mappings.
- Primary owner: junior backend engineer.
- Reviewer: Pod B lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: `app/services/sheshnaag_service.py`, `app/services/import_service.py`, tests.
- Dependencies: WS1-T2, WS1-T3, existing SBOM/VEX import support.
- Implementation steps:
  - Use software components and asset links in addition to `installed_software`.
  - Distinguish direct product matches from inferred package matches.
  - Incorporate VEX statuses into candidate explainability.
  - Add confidence levels per match source.
  - Add fallback logic when SBOM data is absent.
- Acceptance criteria:
  - Candidate relevance is no longer mostly based on coarse asset software strings.

### WS2 Ticket WS2-T6

- Title: Add candidate explainability citations beyond KEV and EPSS.
- Primary owner: junior backend engineer.
- Reviewer: Pod A lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: `app/services/sheshnaag_service.py`, tests.
- Dependencies: WS1-T2, WS1-T3, WS1-T6, WS1-T7.
- Implementation steps:
  - Add advisory citations.
  - Add package source citations.
  - Add VEX-related citations.
  - Add asset match rationale.
  - Keep citation payload normalized.
- Acceptance criteria:
  - Operators can answer "why is this candidate ranked here" from the payload alone.

### WS2 Ticket WS2-T7

- Title: Add candidate assignment metadata and workload views.
- Primary owner: junior backend engineer.
- Reviewer: Pod B lead.
- Estimate: 210 minutes.
- Review estimate: 30 minutes.
- Files: `app/models/sheshnaag.py`, `app/services/sheshnaag_service.py`, tests.
- Dependencies: WS2-T2.
- Implementation steps:
  - Add assignment timestamps.
  - Add assigned-by field.
  - Add per-analyst queue counts.
  - Add "unassigned only" and "mine" style backend support.
- Acceptance criteria:
  - Assignment is not just a name string.

### WS2 Ticket WS2-T8

- Title: Build dedicated integration tests for candidate APIs.
- Primary owner: junior QA engineer.
- Reviewer: Pod H lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: `tests/integration/*`.
- Dependencies: WS2-T3, WS2-T4, WS2-T5.
- Implementation steps:
  - Add list tests.
  - Add filter tests.
  - Add action tests.
  - Add invalid transition tests.
  - Add duplicate merge tests.
- Acceptance criteria:
  - Candidate backend is covered by integration tests, not only service unit tests.

## 24. WS3 Overview

- Objective: create the real candidate queue and analyst triage UI.
- Pod owner: Pod G.
- Supporting pods: Pod B, Pod H.
- Blocking risk: medium.
- Parallelization impact: high.
- Must start by: Week 3.
- Must reach useful completion by: Week 6.

### WS3 Missing Capabilities

- candidate queue page
- candidate details page
- filter panel
- score explanation UI
- assignment UI
- defer and reject UI
- duplicate merge UI
- queue empty states
- stale feed warning UX

### WS3 Ticket WS3-T1

- Title: Add Sheshnaag operator route map to the frontend.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: `frontend/src/App.tsx`, `frontend/src/components/Layout.tsx`, route pages.
- Dependencies: WS0-T3.
- Implementation steps:
  - Add route scaffolds for Intel Dashboard, Candidate Queue, Recipe Builder, Run Console, Evidence Explorer, Artifact Forge, Provenance Center, Analyst Ledger, and Disclosure Bundles.
  - Keep the marketing story page available.
  - Add navigation entries behind a feature flag if needed.
  - Add route-level loading boundaries.
- Acceptance criteria:
  - The frontend no longer routes only to the marketing page.

### WS3 Ticket WS3-T2

- Title: Add candidate API client bindings.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 180 minutes.
- Review estimate: 20 minutes.
- Files: `frontend/src/api.ts`, `frontend/src/types.ts`.
- Dependencies: WS2-T3, WS2-T4.
- Implementation steps:
  - Add `getIntelOverview`.
  - Add `getCandidates`.
  - Add `assignCandidate`.
  - Add `deferCandidate`.
  - Add `rejectCandidate`.
  - Add `mergeCandidateDuplicate`.
  - Add type definitions and request helpers.
- Acceptance criteria:
  - The frontend can call the Sheshnaag candidate APIs directly.

### WS3 Ticket WS3-T3

- Title: Build candidate queue list page.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: `frontend/src/pages/CandidateQueuePage.tsx`, styles, small components.
- Dependencies: WS3-T2.
- Implementation steps:
  - Render candidate table or card list.
  - Show score, KEV, EPSS, patch status, environment fit, and assignment.
  - Add filter controls.
  - Add sorting controls.
  - Add loading, empty, and error states.
  - Make row selection drive detail view.
- Acceptance criteria:
  - Analysts can choose the next research target from the UI.

### WS3 Ticket WS3-T4

- Title: Build candidate detail panel.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: candidate detail component files.
- Dependencies: WS3-T3.
- Implementation steps:
  - Show full explainability factors.
  - Show citations.
  - Show asset match summary.
  - Show package and product information.
  - Show status history if available.
  - Show action buttons.
- Acceptance criteria:
  - Candidate detail answers "why this matters" clearly.

### WS3 Ticket WS3-T5

- Title: Build candidate assignment and transition actions.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: candidate action components.
- Dependencies: WS3-T4, WS2-T3.
- Implementation steps:
  - Add assign flow.
  - Add defer flow.
  - Add reject flow.
  - Add restore flow.
  - Add merge duplicate flow.
  - Add optimistic or refresh behavior.
  - Add confirmation dialogs.
- Acceptance criteria:
  - The full candidate action set is usable in the UI.

### WS3 Ticket WS3-T6

- Title: Build intel freshness cards on the candidate surface.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 180 minutes.
- Review estimate: 20 minutes.
- Files: candidate page, dashboard components.
- Dependencies: WS1-T8.
- Implementation steps:
  - Render feed freshness cards.
  - Show stale status.
  - Show last sync time.
  - Show latest error summary when present.
  - Link stale data states to candidate confidence messaging.
- Acceptance criteria:
  - Operators see feed freshness without leaving the queue.

### WS3 Ticket WS3-T7

- Title: Add frontend tests for candidate queue behavior.
- Primary owner: junior frontend engineer.
- Reviewer: Pod H lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: frontend test files.
- Dependencies: WS3-T3, WS3-T4, WS3-T5.
- Implementation steps:
  - Add render tests.
  - Add filter interaction tests.
  - Add action button tests.
  - Add error state tests.
  - Add loading state tests.
- Acceptance criteria:
  - Candidate queue UI is not manually verified only.

## 25. WS4 Overview

- Objective: turn the current simulated lab provider into a real constrained Linux validation plane.
- Pod owner: Pod C.
- Supporting pods: Pod D, Pod F, Pod H.
- Blocking risk: very high.
- Parallelization impact: very high.
- Must start by: Week 2.
- Must reach useful completion by: Week 7.

### WS4 Missing Capabilities

- actual container execution
- lifecycle state transitions
- template catalog beyond Kali
- host-to-guest artifact transfer
- boot, stop, teardown, and destroy APIs
- health checks
- workspace retention policies
- network policy enforcement
- explicit run failure diagnostics
- provider abstraction for future Lima support

### WS4 Ticket WS4-T1

- Title: Expand provider interface to cover full lifecycle methods.
- Primary owner: junior backend engineer.
- Reviewer: Pod C lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: `app/lab/interfaces.py`, `app/services/sheshnaag_service.py`, tests.
- Dependencies: WS0-T3.
- Implementation steps:
  - Add methods for `plan`, `create`, `boot`, `health`, `stop`, `teardown`, and `destroy`.
  - Define common provider result payloads.
  - Define status vocabulary.
  - Define error vocabulary.
  - Define retry guidance fields.
  - Update existing provider to implement no-op or placeholder versions where needed.
  - Add unit tests for interface contract assumptions.
- Acceptance criteria:
  - Lifecycle states are first-class concepts.
  - Future providers can plug in cleanly.

### WS4 Ticket WS4-T2

- Title: Make Docker provider execute real constrained runs.
- Primary owner: junior backend engineer.
- Reviewer: Pod C lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: `app/lab/docker_kali_provider.py`, tests.
- Dependencies: WS4-T1.
- Implementation steps:
  - Replace `docker version` stub behavior with actual run creation.
  - Generate deterministic container names.
  - Create ephemeral workspaces under a dedicated root.
  - Mount only approved paths.
  - Capture container ID and state.
  - Handle launch timeout.
  - Handle non-zero exit codes.
  - Capture stdout and stderr references without flooding the DB.
  - Preserve dry-run mode.
  - Keep simulated mode for non-Docker dev environments.
- Acceptance criteria:
  - A run in `execute` mode launches a real container.
  - Run state reflects actual execution outcome.

### WS4 Ticket WS4-T3

- Title: Add lifecycle APIs for plan, launch, stop, teardown, and destroy.
- Primary owner: junior backend engineer.
- Reviewer: Pod C lead.
- Estimate: 360 minutes.
- Review estimate: 60 minutes.
- Files: `app/api/routes/run_routes.py`, `app/services/sheshnaag_service.py`, tests.
- Dependencies: WS4-T1, WS4-T2.
- Implementation steps:
  - Separate run planning from launching.
  - Add stop route.
  - Add teardown route.
  - Add destroy route.
  - Add run state validation to each action.
  - Prevent destructive transitions from invalid states.
  - Add event logging for each lifecycle action.
- Acceptance criteria:
  - Operators can control run lifecycle from the API.

### WS4 Ticket WS4-T4

- Title: Add run health checking and guest lifecycle telemetry.
- Primary owner: junior backend engineer.
- Reviewer: Pod D lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: provider modules, run service, tests.
- Dependencies: WS4-T2.
- Implementation steps:
  - Define health statuses for booting, ready, unhealthy, stopped, destroyed, and errored.
  - Add polling hooks for running containers.
  - Record health events in `RunEvent`.
  - Make run details show latest health state.
  - Add timeout rules and unhealthy run handling.
- Acceptance criteria:
  - Run console can present real guest health rather than static state strings.

### WS4 Ticket WS4-T5

- Title: Add template catalog for Ubuntu, Debian, and Rocky.
- Primary owner: junior backend engineer.
- Reviewer: Pod C lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: `app/models/sheshnaag.py`, seed logic, provider configs, tests.
- Dependencies: WS4-T1.
- Implementation steps:
  - Define base template metadata for each distro.
  - Add selection rules and compatibility hints.
  - Persist template catalog rows.
  - Expose template listing API if needed.
  - Add tests for template lookup and defaults.
- Acceptance criteria:
  - Sheshnaag can plan labs against more than Kali.

### WS4 Ticket WS4-T6

- Title: Add host-to-guest artifact transfer with checksums.
- Primary owner: junior backend engineer.
- Reviewer: Pod C lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: provider module, recipe schema handling, tests.
- Dependencies: WS4-T2, WS5-T2.
- Implementation steps:
  - Define uploadable input artifact metadata in recipe content.
  - Copy artifacts into the ephemeral workspace.
  - Hash artifacts before and after placement.
  - Reject artifacts that fail checksum verification.
  - Record artifact transfer events.
  - Add cleanup behavior.
- Acceptance criteria:
  - Inputs can be safely and audibly transferred into the guest workspace.

### WS4 Ticket WS4-T7

- Title: Enforce network policy constraints in the Docker provider.
- Primary owner: junior backend engineer.
- Reviewer: security lead.
- Estimate: 360 minutes.
- Review estimate: 60 minutes.
- Files: provider module, tests, docs.
- Dependencies: WS4-T2.
- Implementation steps:
  - Define allowed network modes.
  - Translate allowlisted hosts into practical policy behavior.
  - Document where Docker alone cannot enforce exact host allowlists.
  - Add conservative fallback behavior.
  - Log effective network policy in run manifests.
  - Add tests for `none`, `bridge`, and policy mismatch scenarios.
- Acceptance criteria:
  - Operators understand the effective policy.
  - Unsafe defaults are not possible.

### WS4 Ticket WS4-T8

- Title: Add workspace retention policy controls.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: provider module, service layer, tests.
- Dependencies: WS4-T2.
- Implementation steps:
  - Define `destroy_immediately`, `retain_exports_only`, and `retain_workspace_until_review` modes.
  - Respect the teardown policy in the provider.
  - Record cleanup outcomes in `RunEvent`.
  - Prevent stale workspace accumulation.
- Acceptance criteria:
  - Workspace handling matches recipe policy and review needs.

### WS4 Ticket WS4-T9

- Title: Prepare a Lima provider contract stub without implementing full Lima execution yet.
- Primary owner: junior backend engineer.
- Reviewer: Pod C lead.
- Estimate: 210 minutes.
- Review estimate: 30 minutes.
- Files: `app/lab/lima_provider.py`, docs, tests.
- Dependencies: WS4-T1.
- Implementation steps:
  - Create a provider module with clear `NotImplemented` boundaries.
  - Document the future snapshot and revert hooks needed.
  - Add a template for VM-backed provider config.
  - Add tests that verify the provider is discoverable but not active by default.
- Acceptance criteria:
  - Future secure mode can be added without redesigning the run contract.

### WS4 Ticket WS4-T10

- Title: Build integration tests for lab lifecycle flows.
- Primary owner: junior QA engineer.
- Reviewer: Pod H lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: `tests/integration/*`, lab scripts.
- Dependencies: WS4-T2, WS4-T3, WS4-T4, WS4-T7.
- Implementation steps:
  - Add dry-run test.
  - Add execute-mode test with Docker available guard.
  - Add stop flow test.
  - Add teardown flow test.
  - Add destroy flow test.
  - Add network policy manifest assertion test.
  - Add artifact transfer checksum test.
- Acceptance criteria:
  - Lifecycle correctness is testable and repeatable.

## 26. WS5 Overview

- Objective: complete the recipe system so validation is reproducible, reviewable, and safe.
- Pod owner: Pod C.
- Supporting pods: Pod G, Pod F, Pod H.
- Blocking risk: high.
- Parallelization impact: high.
- Must start by: Week 3.
- Must reach useful completion by: Week 7.

### WS5 Missing Capabilities

- formal recipe schema validation
- draft-save-launch frontend flow
- dry-run validation UX
- collector selection UX
- template selection UX
- acknowledgement workflow UX
- sign-off policy depth
- recipe diffing
- recipe linting
- recipe import and export

### WS5 Ticket WS5-T1

- Title: Define formal recipe schema and validation rules.
- Primary owner: junior backend engineer.
- Reviewer: Pod C lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: schema module, route validation, tests.
- Dependencies: WS4-T1.
- Implementation steps:
  - Convert implicit recipe content shape into an explicit schema.
  - Validate network policy.
  - Validate collectors.
  - Validate mounts.
  - Validate artifact inputs.
  - Validate teardown policy.
  - Validate risk level and acknowledgement rules.
  - Add clear validation errors.
- Acceptance criteria:
  - Invalid recipe content is rejected before persistence or launch.

### WS5 Ticket WS5-T2

- Title: Add recipe linting and dry-run validation.
- Primary owner: junior backend engineer.
- Reviewer: Pod C lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: recipe service, new lint helpers, tests.
- Dependencies: WS5-T1.
- Implementation steps:
  - Add a lint endpoint or service method.
  - Return warnings and errors separately.
  - Flag risky configurations.
  - Flag unsupported collector combinations.
  - Flag missing required inputs.
  - Flag template and distro mismatches.
- Acceptance criteria:
  - Analysts can understand recipe problems before launch.

### WS5 Ticket WS5-T3

- Title: Add recipe revision diff support.
- Primary owner: junior backend engineer.
- Reviewer: senior backend engineer.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: recipe service, tests.
- Dependencies: WS5-T1.
- Implementation steps:
  - Compare revision content snapshots.
  - Produce machine-readable and human-readable diffs.
  - Highlight policy-relevant changes.
  - Highlight risk-level changes.
  - Highlight collector and network changes.
- Acceptance criteria:
  - Reviewers can see what changed between revisions.

### WS5 Ticket WS5-T4

- Title: Add recipe sign-off policy depth.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: recipe models, service layer, tests.
- Dependencies: WS5-T1.
- Implementation steps:
  - Add policy for which risk levels need one or two sign-offs.
  - Add restricted capabilities list.
  - Add reviewer role restrictions.
  - Add acknowledgement copy storage.
  - Record who acknowledged what text and when.
- Acceptance criteria:
  - Sensitive runs are gated by explicit policy, not only a boolean.

### WS5 Ticket WS5-T5

- Title: Build recipe builder API client and route bindings.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 180 minutes.
- Review estimate: 20 minutes.
- Files: `frontend/src/api.ts`, `frontend/src/types.ts`.
- Dependencies: WS5-T1, WS5-T2, WS5-T3.
- Implementation steps:
  - Add recipe list bindings.
  - Add recipe create bindings.
  - Add recipe revision bindings.
  - Add recipe approve bindings.
  - Add recipe lint bindings.
- Acceptance criteria:
  - Frontend can drive the recipe system directly.

### WS5 Ticket WS5-T6

- Title: Build recipe builder UI shell.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: `frontend/src/pages/RecipeBuilderPage.tsx`, components, styles.
- Dependencies: WS5-T5.
- Implementation steps:
  - Add template selector.
  - Add distro selector.
  - Add command editor.
  - Add collector multi-select.
  - Add network policy editor.
  - Add teardown policy editor.
  - Add risk level selector.
  - Add save draft action.
  - Add create revision action.
  - Add approve action.
- Acceptance criteria:
  - A recipe can be authored and revised through the UI.

### WS5 Ticket WS5-T7

- Title: Build recipe diff and lint results UI.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: recipe builder components.
- Dependencies: WS5-T3, WS5-T6.
- Implementation steps:
  - Show lint warnings.
  - Show blocking errors.
  - Show revision diff view.
  - Highlight risk-relevant changes.
  - Prevent launch when lint errors remain.
- Acceptance criteria:
  - Reviewers can safely approve recipe revisions.

### WS5 Ticket WS5-T8

- Title: Build recipe system tests.
- Primary owner: junior QA engineer.
- Reviewer: Pod H lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: backend and frontend test files.
- Dependencies: WS5-T2, WS5-T6, WS5-T7.
- Implementation steps:
  - Add schema validation tests.
  - Add lint tests.
  - Add revision diff tests.
  - Add builder UI tests.
  - Add approve flow tests.
- Acceptance criteria:
  - Recipe behavior is covered end-to-end.

## 27. WS6 Overview

- Objective: replace synthetic evidence with real evidence collection.
- Pod owner: Pod D.
- Supporting pods: Pod C, Pod E, Pod H.
- Blocking risk: very high.
- Parallelization impact: very high.
- Must start by: Week 4.
- Must reach useful completion by: Week 8.

### WS6 Missing Capabilities

- real process trees
- real package inventory diffs
- real file changes
- real network connection logs
- real DNS requests
- real HTTP metadata
- real service logs
- basic PCAP
- osquery snapshots
- evidence storage paths
- evidence indexing
- evidence timeline view contract

### WS6 Ticket WS6-T1

- Title: Replace synthetic collector registry with pluggable real collector framework.
- Primary owner: junior backend engineer.
- Reviewer: Pod D lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: `app/lab/collectors.py`, new collector modules, tests.
- Dependencies: WS4-T1.
- Implementation steps:
  - Keep the collector interface.
  - Split each collector into its own module.
  - Add collector configuration support.
  - Add pre-run hook support.
  - Add post-run hook support.
  - Add artifact path output support.
  - Add collector error reporting.
  - Keep a synthetic fallback collector for non-live test mode only.
- Acceptance criteria:
  - Real collectors can be enabled independently.

### WS6 Ticket WS6-T2

- Title: Implement process tree collector.
- Primary owner: junior backend engineer.
- Reviewer: Pod D lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: process collector module, tests.
- Dependencies: WS6-T1, WS4-T2.
- Implementation steps:
  - Determine how to collect process data from container runtime or guest tools.
  - Capture parent-child process relationships.
  - Normalize into a process tree payload.
  - Store raw capture output.
  - Compute artifact hash.
  - Add collector error handling.
- Acceptance criteria:
  - Evidence includes real process execution trees.

### WS6 Ticket WS6-T3

- Title: Implement package inventory before-and-after collector.
- Primary owner: junior backend engineer.
- Reviewer: Pod D lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: package collector module, tests.
- Dependencies: WS6-T1, WS4-T2.
- Implementation steps:
  - Run pre-execution package inventory query.
  - Run post-execution package inventory query.
  - Compute diff.
  - Store baseline, final, and diff summaries.
  - Normalize package names and versions.
- Acceptance criteria:
  - Package state change evidence is real and diffable.

### WS6 Ticket WS6-T4

- Title: Implement file and path change collector.
- Primary owner: junior backend engineer.
- Reviewer: Pod D lead.
- Estimate: 360 minutes.
- Review estimate: 60 minutes.
- Files: file diff collector module, tests.
- Dependencies: WS6-T1, WS4-T2.
- Implementation steps:
  - Capture pre-run directory snapshot for relevant paths.
  - Capture post-run snapshot.
  - Compute added, modified, and deleted files.
  - Hash changed files where safe.
  - Enforce size limits.
  - Record truncated capture warnings.
- Acceptance criteria:
  - File delta evidence is real and bounded.

### WS6 Ticket WS6-T5

- Title: Implement network metadata collector.
- Primary owner: junior backend engineer.
- Reviewer: Pod D lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: network collector module, tests.
- Dependencies: WS6-T1, WS4-T7.
- Implementation steps:
  - Capture connection tuples.
  - Capture DNS lookups.
  - Capture HTTP metadata headers where legal and configured.
  - Annotate whether traffic matched the allowlist.
  - Summarize egress events.
- Acceptance criteria:
  - Network evidence is policy-aware and real.

### WS6 Ticket WS6-T6

- Title: Implement service log collector.
- Primary owner: junior backend engineer.
- Reviewer: Pod D lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: service log collector module, tests.
- Dependencies: WS6-T1, WS4-T2.
- Implementation steps:
  - Identify log sources from recipe configuration.
  - Capture bounded log excerpts.
  - Tag timestamps and service names.
  - Store raw and summarized forms.
- Acceptance criteria:
  - Service logs are preserved as evidence artifacts.

### WS6 Ticket WS6-T7

- Title: Integrate osquery snapshot collector.
- Primary owner: junior backend engineer.
- Reviewer: Pod D lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: osquery collector module, provider setup, tests.
- Dependencies: WS6-T1, WS4-T2.
- Implementation steps:
  - Decide how osquery is installed or available in the guest.
  - Define a curated query pack.
  - Capture process, package, file, listening port, and user context snapshots.
  - Normalize query results.
  - Bound output size.
  - Record failed query diagnostics.
- Acceptance criteria:
  - osquery evidence is available for configured runs.

### WS6 Ticket WS6-T8

- Title: Add basic PCAP capture.
- Primary owner: junior backend engineer.
- Reviewer: security lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: PCAP collector module, provider config, tests.
- Dependencies: WS6-T1, WS4-T7.
- Implementation steps:
  - Decide capture scope and default disable posture.
  - Add feature flag.
  - Capture PCAP to bounded files.
  - Add metadata summary artifact separate from the raw file.
  - Enforce retention limits.
  - Redact or reject unsafe configurations.
- Acceptance criteria:
  - PCAP capture exists but is controlled and policy-bound.

### WS6 Ticket WS6-T9

- Title: Persist evidence storage paths and retrieval metadata.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: `app/models/sheshnaag.py`, service layer, tests.
- Dependencies: WS6-T2 through WS6-T8.
- Implementation steps:
  - Persist storage path.
  - Persist content type.
  - Persist size.
  - Persist capture time range.
  - Persist collector name and version.
  - Persist truncated flag.
- Acceptance criteria:
  - Evidence rows point to actual collected artifacts.

### WS6 Ticket WS6-T10

- Title: Add evidence timeline payload support.
- Primary owner: junior backend engineer.
- Reviewer: Pod E lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: evidence service, run service, tests.
- Dependencies: WS6-T2 through WS6-T9.
- Implementation steps:
  - Add normalized timestamps to evidence artifacts.
  - Build a timeline aggregation payload.
  - Group artifacts by collection stage and time.
  - Preserve ordering.
  - Add tests for mixed collector outputs.
- Acceptance criteria:
  - Frontend can render a run timeline from evidence timestamps.

### WS6 Ticket WS6-T11

- Title: Build evidence pipeline integration tests.
- Primary owner: junior QA engineer.
- Reviewer: Pod H lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: `tests/integration/*`, lab fixtures.
- Dependencies: WS6-T2 through WS6-T10.
- Implementation steps:
  - Add live-run evidence tests.
  - Assert artifact kinds and storage metadata.
  - Assert collector failures do not erase successful evidence.
  - Assert bounded capture behavior.
  - Assert timeline ordering.
- Acceptance criteria:
  - Real evidence collection is regression-tested.

## 28. WS7 Overview

- Objective: integrate curated runtime telemetry tools for defensive observation.
- Pod owner: Pod D.
- Supporting pods: Pod E, Pod H, security lead.
- Blocking risk: high.
- Parallelization impact: high.
- Must start by: Week 6.
- Must reach useful completion by: Week 10.

### WS7 Missing Capabilities

- Tracee real integration
- Falco integration
- Tetragon integration
- normalized event envelope
- event routing
- event-to-finding translation
- policy packs
- collector health telemetry
- overhead measurement

### WS7 Ticket WS7-T1

- Title: Define normalized runtime event envelope.
- Primary owner: junior backend engineer.
- Reviewer: Pod D lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: telemetry normalization module, docs, tests.
- Dependencies: WS6-T1.
- Implementation steps:
  - Define common fields for source tool, time, process, parent process, file, network, and severity.
  - Define optional evidence file references.
  - Define policy match fields.
  - Define raw event preservation fields.
  - Add schema tests.
- Acceptance criteria:
  - Falco, Tracee, and Tetragon can map into one event envelope.

### WS7 Ticket WS7-T2

- Title: Implement Tracee collector integration.
- Primary owner: junior backend engineer.
- Reviewer: Pod D lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: tracee collector module, provider config, tests.
- Dependencies: WS7-T1, WS4-T2.
- Implementation steps:
  - Add feature flag.
  - Determine run-time invocation strategy.
  - Capture Tracee output to a bounded file.
  - Normalize events into the envelope.
  - Emit collector health metadata.
  - Add failure diagnostics.
- Acceptance criteria:
  - Tracee events can be collected and normalized in real runs.

### WS7 Ticket WS7-T3

- Title: Implement Falco collector integration.
- Primary owner: junior backend engineer.
- Reviewer: Pod D lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: Falco collector module, policy configs, tests.
- Dependencies: WS7-T1, WS4-T2.
- Implementation steps:
  - Add feature flag.
  - Decide on how Falco rules are loaded.
  - Capture findings and bounded raw output.
  - Normalize into the event envelope.
  - Record policy pack version.
- Acceptance criteria:
  - Falco findings appear as evidence and normalized events.

### WS7 Ticket WS7-T4

- Title: Implement Tetragon collector integration.
- Primary owner: junior backend engineer.
- Reviewer: Pod D lead.
- Estimate: 480 minutes.
- Review estimate: 60 minutes.
- Files: Tetragon collector module, tests, docs.
- Dependencies: WS7-T1, WS4-T2.
- Implementation steps:
  - Add feature flag.
  - Decide whether this is supported only on specific hosts or future secure mode.
  - Build a compatibility matrix.
  - Normalize Tetragon events.
  - Record unsupported environment behavior clearly.
- Acceptance criteria:
  - Tetragon support is explicit, safe, and does not silently fail.

### WS7 Ticket WS7-T5

- Title: Add event-to-finding translation layer.
- Primary owner: junior backend engineer.
- Reviewer: Pod E lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: finding translation module, tests.
- Dependencies: WS7-T2, WS7-T3.
- Implementation steps:
  - Define detection-worthy patterns.
  - Group similar runtime events.
  - Create summarized findings with linked raw evidence.
  - Add severity scoring.
  - Add false-positive notes where needed.
- Acceptance criteria:
  - Operators do not have to read raw telemetry to see the main findings.

### WS7 Ticket WS7-T6

- Title: Add telemetry policy packs for enterprise validation patterns.
- Primary owner: junior security engineer.
- Reviewer: security lead.
- Estimate: 360 minutes.
- Review estimate: 60 minutes.
- Files: policy pack files, docs, tests.
- Dependencies: WS7-T2, WS7-T3.
- Implementation steps:
  - Define starter policies for privilege changes.
  - Define starter policies for suspicious execution chains.
  - Define starter policies for fileless indicators.
  - Define starter policies for blocked egress behavior.
  - Version the policy packs.
- Acceptance criteria:
  - Runtime telemetry reflects curated enterprise validation priorities.

### WS7 Ticket WS7-T7

- Title: Add collector health and overhead telemetry.
- Primary owner: junior backend engineer.
- Reviewer: Pod H lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: collector modules, service layer, tests.
- Dependencies: WS7-T2, WS7-T3, WS7-T4.
- Implementation steps:
  - Record collector start time.
  - Record collector end time.
  - Record output size.
  - Record tool errors.
  - Record if collector was skipped for compatibility reasons.
- Acceptance criteria:
  - Operators can distinguish no findings from collector failure.

### WS7 Ticket WS7-T8

- Title: Build runtime telemetry integration tests.
- Primary owner: junior QA engineer.
- Reviewer: Pod H lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: `tests/integration/*`.
- Dependencies: WS7-T1 through WS7-T7.
- Implementation steps:
  - Add normalized event schema tests.
  - Add collector flag tests.
  - Add health metadata tests.
  - Add event-to-finding translation tests.
- Acceptance criteria:
  - Telemetry integrations are testable and predictable.

## 29. WS8 Overview

- Objective: generate evidence-backed defensive artifacts and review them properly.
- Pod owner: Pod E.
- Supporting pods: Pod D, Pod F, Pod G, Pod H.
- Blocking risk: high.
- Parallelization impact: high.
- Must start by: Week 7.
- Must reach useful completion by: Week 10.

### WS8 Missing Capabilities

- evidence-backed Sigma generation
- richer Falco rule generation
- Suricata rule generation
- YARA rule generation
- OpenVEX suggestion outputs
- review workflow
- artifact states beyond draft
- export formats
- false-positive feedback

### WS8 Ticket WS8-T1

- Title: Redesign artifact generator around evidence pattern extractors.
- Primary owner: junior backend engineer.
- Reviewer: Pod E lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: `app/lab/artifact_generator.py`, new extractor modules, tests.
- Dependencies: WS6-T10, WS7-T5.
- Implementation steps:
  - Separate evidence parsing from rule rendering.
  - Add extractors for process patterns.
  - Add extractors for file patterns.
  - Add extractors for network patterns.
  - Add extractors for runtime finding summaries.
  - Create normalized intermediate detection candidates.
- Acceptance criteria:
  - Artifact generation no longer depends on the first evidence row only.

### WS8 Ticket WS8-T2

- Title: Improve Sigma generation from evidence-backed patterns.
- Primary owner: junior backend engineer.
- Reviewer: Pod E lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: artifact generator modules, tests.
- Dependencies: WS8-T1.
- Implementation steps:
  - Map process and log patterns to Sigma-friendly fields.
  - Add confidence notes.
  - Include provenance references.
  - Support multiple candidate rules per run where justified.
- Acceptance criteria:
  - Sigma output is traceable to actual observed evidence.

### WS8 Ticket WS8-T3

- Title: Improve Falco rule generation.
- Primary owner: junior backend engineer.
- Reviewer: Pod E lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: artifact generator modules, tests.
- Dependencies: WS8-T1.
- Implementation steps:
  - Map runtime events to Falco conditions.
  - Generate human-readable outputs.
  - Include caveats when signal confidence is medium or low.
  - Link the generated rule to supporting evidence IDs.
- Acceptance criteria:
  - Falco output is more than a static template.

### WS8 Ticket WS8-T4

- Title: Add Suricata candidate generation for network-observable runs.
- Primary owner: junior backend engineer.
- Reviewer: Pod E lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: artifact generator modules, tests.
- Dependencies: WS6-T5, WS6-T8, WS8-T1.
- Implementation steps:
  - Define what network evidence is sufficient to generate a rule.
  - Generate rule candidates from DNS, HTTP metadata, or PCAP-derived summaries.
  - Add suppression notes for low-confidence cases.
  - Skip generation when the evidence is too weak.
- Acceptance criteria:
  - Suricata candidates are produced only when meaningful.

### WS8 Ticket WS8-T5

- Title: Add YARA candidate generation for extracted files or binaries.
- Primary owner: junior backend engineer.
- Reviewer: Pod E lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: artifact generator modules, tests.
- Dependencies: WS6-T4, WS8-T1.
- Implementation steps:
  - Define when YARA generation is permitted.
  - Build safe string extraction rules.
  - Avoid overfitting on trivial noise.
  - Link each YARA candidate to evidence hashes.
- Acceptance criteria:
  - YARA candidates are available when file artifacts justify them.

### WS8 Ticket WS8-T6

- Title: Add mitigation and workaround summary generator v2.
- Primary owner: junior backend engineer.
- Reviewer: Pod E lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: generator modules, tests.
- Dependencies: WS8-T1, WS2-T5.
- Implementation steps:
  - Use version applicability.
  - Use patch availability.
  - Use VEX status.
  - Use exposed service mapping.
  - Render prioritized mitigation steps.
- Acceptance criteria:
  - Mitigation output reflects the tenant and the evidence.

### WS8 Ticket WS8-T7

- Title: Add OpenVEX suggestion outputs.
- Primary owner: junior backend engineer.
- Reviewer: Pod E lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: artifact generator modules, tests.
- Dependencies: WS2-T5, WS8-T1.
- Implementation steps:
  - Define suggested statuses for affected, not affected, fixed, and under investigation.
  - Include evidence references and confidence notes.
  - Keep output suggestion-only unless explicitly approved.
- Acceptance criteria:
  - VEX-style suggestions can be generated from run findings.

### WS8 Ticket WS8-T8

- Title: Add artifact review state machine.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: models, services, routes, tests.
- Dependencies: WS8-T1.
- Implementation steps:
  - Add states such as draft, under_review, approved, rejected, superseded.
  - Add reviewer identity and rationale fields.
  - Add transition validation.
  - Add audit trail entries.
- Acceptance criteria:
  - A successful run can produce at least one reviewed artifact.

### WS8 Ticket WS8-T9

- Title: Add false-positive feedback capture for artifacts.
- Primary owner: junior backend engineer.
- Reviewer: Pod E lead.
- Estimate: 210 minutes.
- Review estimate: 30 minutes.
- Files: artifact routes, service modules, tests.
- Dependencies: WS8-T8.
- Implementation steps:
  - Define feedback payload.
  - Link feedback to artifact IDs.
  - Persist author and timestamp.
  - Add retrieval support.
- Acceptance criteria:
  - Artifact quality can improve over time with explicit feedback.

### WS8 Ticket WS8-T10

- Title: Build artifact forge frontend.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: `frontend/src/pages/ArtifactForgePage.tsx`, API bindings, components.
- Dependencies: WS8-T2 through WS8-T9.
- Implementation steps:
  - Show generated artifacts by type.
  - Show evidence links.
  - Show review states.
  - Show approval actions.
  - Show feedback actions.
  - Add export/download buttons for approved artifacts.
- Acceptance criteria:
  - Artifact forge is a real operator surface.

### WS8 Ticket WS8-T11

- Title: Build artifact integration tests.
- Primary owner: junior QA engineer.
- Reviewer: Pod H lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: `tests/integration/*`.
- Dependencies: WS8-T2 through WS8-T10.
- Implementation steps:
  - Add generation tests.
  - Add review transition tests.
  - Add feedback tests.
  - Add export availability tests.
- Acceptance criteria:
  - Artifact forge behavior is regression tested.

## 30. WS9 Overview

- Objective: make every run defensible, attributable, and reviewable.
- Pod owner: Pod F.
- Supporting pods: Pod C, Pod E, Pod G, Pod H.
- Blocking risk: high.
- Parallelization impact: high.
- Must start by: Week 7.
- Must reach useful completion by: Week 10.

### WS9 Missing Capabilities

- richer attestation payloads
- stronger signing options
- evidence hash linkage
- chain-of-custody lineage
- provenance center UI
- ledger scoring rules
- contribution weighting
- review chain visibility

### WS9 Ticket WS9-T1

- Title: Define attestation payload schema v1.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: attestation module, docs, tests.
- Dependencies: WS0-T3.
- Implementation steps:
  - Define required fields for run manifest attestation.
  - Define required fields for disclosure bundle attestation.
  - Include recipe revision digest.
  - Include evidence set hashes.
  - Include artifact hashes.
  - Include analyst and workstation references.
  - Include tool version references.
- Acceptance criteria:
  - Attestation payload structure is explicit and stable.

### WS9 Ticket WS9-T2

- Title: Upgrade attestation implementation beyond simple local digest wrapper.
- Primary owner: junior backend engineer.
- Reviewer: security lead.
- Estimate: 360 minutes.
- Review estimate: 60 minutes.
- Files: `app/lab/attestation.py`, config, tests.
- Dependencies: WS9-T1.
- Implementation steps:
  - Keep local digest mode for development.
  - Add pluggable signing backend support.
  - Add explicit signer metadata.
  - Add signature algorithm field.
  - Add verification helpers.
  - Add failure modes for unavailable signing backend.
- Acceptance criteria:
  - Signing is pluggable and verification-friendly.

### WS9 Ticket WS9-T3

- Title: Link all evidence and artifacts into provenance records.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: service layer, models, tests.
- Dependencies: WS6-T9, WS8-T8, WS9-T1.
- Implementation steps:
  - Record evidence hashes in run provenance.
  - Record artifact hashes in run provenance.
  - Record recipe revision digest in run provenance.
  - Record workstation fingerprint linkage.
  - Record review decisions in provenance summary.
- Acceptance criteria:
  - A run can be traced end-to-end without manual DB joins.

### WS9 Ticket WS9-T4

- Title: Expand ledger scoring rules and event types.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: service layer, tests.
- Dependencies: WS9-T3.
- Implementation steps:
  - Add scoring rules for recipe authorship.
  - Add scoring rules for approved artifacts.
  - Add scoring rules for accepted disclosures.
  - Add scoring rules for peer review contribution.
  - Add payload details that explain the score.
- Acceptance criteria:
  - Ledger rows are meaningful for performance and attribution use cases.

### WS9 Ticket WS9-T5

- Title: Add contribution weighting and shared credit support.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: models, services, tests.
- Dependencies: WS9-T4.
- Implementation steps:
  - Define multi-actor contribution payloads.
  - Add co-author support.
  - Add reviewer support.
  - Add weighted split rules.
  - Add tests for split scoring.
- Acceptance criteria:
  - Team work does not collapse into a single-owner ledger.

### WS9 Ticket WS9-T6

- Title: Build provenance center API enrichment.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: provenance service, routes, tests.
- Dependencies: WS9-T3.
- Implementation steps:
  - Expand provenance payload beyond raw attestation rows.
  - Add manifest summary.
  - Add evidence and artifact linkage counts.
  - Add review history summary.
  - Add export history summary.
- Acceptance criteria:
  - Frontend can render a full provenance center from one or two API calls.

### WS9 Ticket WS9-T7

- Title: Build provenance center frontend.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: `frontend/src/pages/ProvenanceCenterPage.tsx`, bindings, components.
- Dependencies: WS9-T6.
- Implementation steps:
  - Render run manifest.
  - Render attestation details.
  - Render hashes and signatures.
  - Render evidence linkage.
  - Render review history.
  - Render export history.
- Acceptance criteria:
  - Provenance center is a first-class surface, not just a raw JSON view.

### WS9 Ticket WS9-T8

- Title: Build analyst ledger frontend.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: `frontend/src/pages/AnalystLedgerPage.tsx`, bindings, components.
- Dependencies: WS9-T4, WS9-T5.
- Implementation steps:
  - Show authored recipes.
  - Show accepted runs.
  - Show approved artifacts.
  - Show disclosures.
  - Show contribution score changes over time.
  - Show peer review contributions.
- Acceptance criteria:
  - The ledger is useful to research leads and analysts.

### WS9 Ticket WS9-T9

- Title: Build provenance and ledger integration tests.
- Primary owner: junior QA engineer.
- Reviewer: Pod H lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: `tests/integration/*`.
- Dependencies: WS9-T2 through WS9-T8.
- Implementation steps:
  - Add attestation verification tests.
  - Add provenance linkage tests.
  - Add ledger scoring tests.
  - Add co-credit tests.
  - Add frontend smoke tests.
- Acceptance criteria:
  - Provenance correctness is verified continuously.

## 31. WS10 Overview

- Objective: turn disclosure bundle records into actual actionable export packages.
- Pod owner: Pod F.
- Supporting pods: Pod E, Pod G, Pod H.
- Blocking risk: high.
- Parallelization impact: medium.
- Must start by: Week 8.
- Must reach useful completion by: Week 11.

### WS10 Missing Capabilities

- vendor disclosure template
- bug bounty template
- research bounty template
- evidence selection
- evidence redaction
- reproducibility appendix
- actual file export
- signed manifest packaging

### WS10 Ticket WS10-T1

- Title: Define disclosure bundle package format.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: docs, bundle service, tests.
- Dependencies: WS9-T1.
- Implementation steps:
  - Decide archive format.
  - Decide manifest structure.
  - Decide file naming conventions.
  - Decide where evidence summaries, full evidence, artifacts, and appendices live.
  - Decide redaction markers.
- Acceptance criteria:
  - Bundle exports have a concrete file format contract.

### WS10 Ticket WS10-T2

- Title: Add destination-specific bundle templates.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: bundle service, template files, tests.
- Dependencies: WS10-T1.
- Implementation steps:
  - Add vendor disclosure template.
  - Add bug bounty report template.
  - Add research bounty report template.
  - Add common manifest appendix.
  - Add reproducibility appendix sections.
- Acceptance criteria:
  - Bundle type meaningfully changes the report content.

### WS10 Ticket WS10-T3

- Title: Add evidence selection and redaction workflow support.
- Primary owner: junior backend engineer.
- Reviewer: security lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: disclosure service, models, routes, tests.
- Dependencies: WS10-T1, WS6-T9.
- Implementation steps:
  - Add evidence include and exclude support.
  - Add redaction note support.
  - Add file-level and field-level redaction metadata.
  - Add warnings for missing core evidence.
  - Preserve the original non-redacted provenance internally.
- Acceptance criteria:
  - External bundles can be tailored safely.

### WS10 Ticket WS10-T4

- Title: Add structured reproduction steps generator.
- Primary owner: junior backend engineer.
- Reviewer: Pod E lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: disclosure service, tests.
- Dependencies: WS5-T1, WS6-T10.
- Implementation steps:
  - Use recipe content, run events, and evidence to draft reproduction steps.
  - Separate environment setup from execution.
  - Separate observed result from expected result.
  - Allow manual override later.
- Acceptance criteria:
  - Bundles include actionable reproduction guidance.

### WS10 Ticket WS10-T5

- Title: Add actual archive export and download support.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: disclosure routes, export service, tests.
- Dependencies: WS10-T1, WS10-T2, WS10-T3, WS10-T4.
- Implementation steps:
  - Create archive builder.
  - Include manifest and signature files.
  - Include selected evidence summaries and allowed raw artifacts.
  - Store archive path and hash.
  - Add download endpoint or signed path response.
- Acceptance criteria:
  - Disclosure bundles are real export packages.

### WS10 Ticket WS10-T6

- Title: Build disclosure bundle frontend.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: `frontend/src/pages/DisclosureBundlesPage.tsx`, bindings, components.
- Dependencies: WS10-T2 through WS10-T5.
- Implementation steps:
  - Show bundle list.
  - Show create bundle flow.
  - Show bundle type selector.
  - Show evidence selection UI.
  - Show redaction notes UI.
  - Show download action.
- Acceptance criteria:
  - Analysts can generate disclosure bundles without using raw APIs.

### WS10 Ticket WS10-T7

- Title: Build disclosure integration tests.
- Primary owner: junior QA engineer.
- Reviewer: Pod H lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: `tests/integration/*`.
- Dependencies: WS10-T2 through WS10-T6.
- Implementation steps:
  - Add bundle creation tests.
  - Add template selection tests.
  - Add redaction behavior tests.
  - Add archive existence and hash tests.
  - Add download tests.
- Acceptance criteria:
  - Disclosure exports are testable and repeatable.

## 32. WS11 Overview

- Objective: complete the operator frontend so Sheshnaag is used through intentional workflows rather than raw API endpoints.
- Pod owner: Pod G.
- Supporting pods: all backend pods, Pod H.
- Blocking risk: medium.
- Parallelization impact: very high.
- Must start by: Week 5.
- Must reach useful completion by: Week 11.

### WS11 Missing Capabilities

- intel dashboard
- candidate queue polish
- recipe builder polish
- run console
- evidence explorer
- artifact forge polish
- provenance center polish
- analyst ledger polish
- disclosure bundle polish
- consistent design system
- mobile-safe layouts
- operator error recovery patterns

### WS11 Ticket WS11-T1

- Title: Build Sheshnaag design system foundations.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: `frontend/src/styles.css`, shared components.
- Dependencies: WS3-T1.
- Implementation steps:
  - Define color variables for operator surfaces.
  - Define spacing scale.
  - Define typography system.
  - Define status pill styles.
  - Define table and detail panel styles.
  - Define empty, error, and loading state components.
  - Define page shell patterns.
- Acceptance criteria:
  - Operator pages feel like one product, not stitched screens.

### WS11 Ticket WS11-T2

- Title: Build Sheshnaag intel dashboard page.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: `frontend/src/pages/IntelDashboardPage.tsx`, components.
- Dependencies: WS1-T8, WS11-T1.
- Implementation steps:
  - Show feed freshness cards.
  - Show candidate count.
  - Show active run count.
  - Show disclosure bundle count.
  - Show source health summaries.
  - Show stale feed warnings.
- Acceptance criteria:
  - The PRD intel dashboard exists as a real page.

### WS11 Ticket WS11-T3

- Title: Build run console page.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: `frontend/src/pages/RunConsolePage.tsx`, components, bindings.
- Dependencies: WS4-T3, WS4-T4.
- Implementation steps:
  - Show guest status.
  - Show execution timeline.
  - Show run transcript.
  - Show collector health.
  - Show policy violations.
  - Show stop and teardown controls.
  - Poll live status when the run is active.
- Acceptance criteria:
  - Operators can monitor validation runs from the UI.

### WS11 Ticket WS11-T4

- Title: Build evidence explorer page.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: `frontend/src/pages/EvidenceExplorerPage.tsx`, components, bindings.
- Dependencies: WS6-T10.
- Implementation steps:
  - Show process tree tab.
  - Show file diff tab.
  - Show package diff tab.
  - Show network tab.
  - Show osquery snapshot tab.
  - Show telemetry findings tab.
  - Show timeline ordering.
- Acceptance criteria:
  - Evidence is explorable without raw JSON inspection.

### WS11 Ticket WS11-T5

- Title: Build run-to-evidence linking UX.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: run console and evidence explorer components.
- Dependencies: WS11-T3, WS11-T4.
- Implementation steps:
  - Make run console deep-link into evidence explorer.
  - Filter explorer by run ID.
  - Highlight newest artifacts.
  - Show collector failures inline.
- Acceptance criteria:
  - Operators can move naturally from run monitoring to evidence review.

### WS11 Ticket WS11-T6

- Title: Build analyst-centered navigation and dashboard landing choice.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 180 minutes.
- Review estimate: 20 minutes.
- Files: layout, navigation, route guards.
- Dependencies: WS11-T1, WS11-T2.
- Implementation steps:
  - Add operator nav group.
  - Preserve marketing nav separately.
  - Choose whether the default route is marketing or operator based on mode flag.
  - Add breadcrumbs.
  - Add active page highlighting.
- Acceptance criteria:
  - Operators are not forced through the marketing page.

### WS11 Ticket WS11-T7

- Title: Add resilient error and retry UX across operator pages.
- Primary owner: junior frontend engineer.
- Reviewer: Pod H lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: shared components, pages, API client.
- Dependencies: WS11-T2 through WS11-T6.
- Implementation steps:
  - Standardize API error display.
  - Add retry buttons.
  - Add polling backoff for run pages.
  - Add empty state explanations.
  - Add permission-denied messaging.
- Acceptance criteria:
  - Operator UX handles failure gracefully.

### WS11 Ticket WS11-T8

- Title: Add frontend smoke test coverage for operator route map.
- Primary owner: junior QA engineer.
- Reviewer: Pod H lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: frontend test files.
- Dependencies: WS11-T2 through WS11-T7.
- Implementation steps:
  - Add route render tests.
  - Add page load smoke tests.
  - Add API mock tests for empty states.
  - Add feature flag route exposure tests.
- Acceptance criteria:
  - The operator frontend is smoke-tested in CI.

## 33. WS12 Overview

- Objective: make the roadmap deliverable and stable through strong testing, CI discipline, and release rehearsals.
- Pod owner: Pod H.
- Supporting pods: all.
- Blocking risk: very high.
- Parallelization impact: very high.
- Must start by: Week 0.
- Must continue through: all weeks.

### WS12 Missing Capabilities

- Sheshnaag integration tests
- Sheshnaag route smoke tests
- Docker-backed live execution test coverage
- frontend route tests
- bundle export tests
- telemetry compatibility tests
- migration discipline
- release rehearsal process

### WS12 Ticket WS12-T1

- Title: Create Sheshnaag integration test suite structure.
- Primary owner: junior QA engineer.
- Reviewer: Pod H lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: `tests/integration/*`, `tests/conftest.py`.
- Dependencies: WS0-T4.
- Implementation steps:
  - Add test modules grouped by workstream.
  - Add shared fixtures for writable tenants.
  - Add helper fixtures for recipe and run setup.
  - Add helper assertions for provenance linkage.
  - Add naming standards.
- Acceptance criteria:
  - New Sheshnaag features land in predictable test files.

### WS12 Ticket WS12-T2

- Title: Add backend smoke test command for Sheshnaag APIs.
- Primary owner: junior QA engineer.
- Reviewer: Pod H lead.
- Estimate: 180 minutes.
- Review estimate: 20 minutes.
- Files: scripts, README, tests.
- Dependencies: WS12-T1.
- Implementation steps:
  - Create a smoke command for intel, candidates, recipes, runs, evidence, artifacts, provenance, ledger, and disclosures.
  - Add a readable summary.
  - Document how to run it locally.
- Acceptance criteria:
  - Team members can validate the major API surfaces quickly.

### WS12 Ticket WS12-T3

- Title: Add frontend smoke test command for Sheshnaag routes.
- Primary owner: junior QA engineer.
- Reviewer: Pod H lead.
- Estimate: 180 minutes.
- Review estimate: 20 minutes.
- Files: frontend test files, package scripts.
- Dependencies: WS11-T8.
- Implementation steps:
  - Add a route smoke test script.
  - Cover all operator pages.
  - Add mock data fixtures for common states.
- Acceptance criteria:
  - UI regressions are caught early.

### WS12 Ticket WS12-T4

- Title: Add live-run guarded test profile.
- Primary owner: junior QA engineer.
- Reviewer: Pod C lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: test config, docs.
- Dependencies: WS4-T2.
- Implementation steps:
  - Add env guard for Docker-dependent tests.
  - Add skip logic for unavailable environments.
  - Add clear documentation.
  - Add a small deterministic recipe fixture.
- Acceptance criteria:
  - Live-run tests are optional but reliable when enabled.

### WS12 Ticket WS12-T5

- Title: Add regression matrix for collector combinations.
- Primary owner: junior QA engineer.
- Reviewer: Pod D lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: tests, docs.
- Dependencies: WS6-T11, WS7-T8.
- Implementation steps:
  - Create baseline collector profile.
  - Create osquery profile.
  - Create Tracee profile.
  - Create Falco profile.
  - Create mixed collector profile.
  - Verify runs complete and evidence manifests are coherent.
- Acceptance criteria:
  - Collector combinations are explicitly tested.

### WS12 Ticket WS12-T6

- Title: Add release rehearsal checklist execution script.
- Primary owner: junior release engineer.
- Reviewer: Pod H lead.
- Estimate: 210 minutes.
- Review estimate: 20 minutes.
- Files: scripts, docs.
- Dependencies: WS0-T6.
- Implementation steps:
  - Create a script that runs build, tests, smoke tests, and export checks.
  - Print pass and fail summary.
  - Document manual follow-up steps.
- Acceptance criteria:
  - Release rehearsals are repeatable.

### WS12 Ticket WS12-T7

- Title: Add test data fixture packs for v1.0, v1.1, and v1.2 use cases.
- Primary owner: junior QA engineer.
- Reviewer: Pod H lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: fixtures, tests.
- Dependencies: WS1 through WS10 feature completeness.
- Implementation steps:
  - Create a v1.0 simple CVE fixture.
  - Create a v1.1 SBOM-heavy fixture.
  - Create a v1.2 disclosure-quality fixture.
  - Add docs for when to use each fixture set.
- Acceptance criteria:
  - Test coverage reflects real use-case variety.

## 34. WS13 Overview

- Objective: enforce the safety and hardening controls promised by the PRD.
- Pod owner: Pod H.
- Supporting pods: Pod C, Pod D, Pod F.
- Blocking risk: very high.
- Parallelization impact: medium.
- Must start by: Week 2.
- Must continue through: all weeks.

### WS13 Missing Capabilities

- stronger host isolation defaults
- capability audit checks
- unsafe mount prevention
- explicit acknowledgement text capture
- egress safety validation
- bundle safety review checks
- misuse safeguards in exports

### WS13 Ticket WS13-T1

- Title: Audit provider defaults against safety policy.
- Primary owner: junior security engineer.
- Reviewer: security lead.
- Estimate: 240 minutes.
- Review estimate: 45 minutes.
- Files: provider module, docs.
- Dependencies: WS4-T2.
- Implementation steps:
  - Review all current Docker flags.
  - Identify missing hardening flags.
  - Identify unsafe default behaviors.
  - Document gaps.
  - Create remediation follow-up tickets if needed.
- Acceptance criteria:
  - The provider’s actual posture is documented and hardened.

### WS13 Ticket WS13-T2

- Title: Add unsafe mount validation rules.
- Primary owner: junior backend engineer.
- Reviewer: security lead.
- Estimate: 180 minutes.
- Review estimate: 30 minutes.
- Files: recipe validation modules, tests.
- Dependencies: WS5-T1.
- Implementation steps:
  - Block host-sensitive paths.
  - Require explicit allowlist for mount roots.
  - Reject writable mounts by default unless policy-approved.
  - Add clear validation errors.
- Acceptance criteria:
  - Unsafe mounts are rejected before launch.

### WS13 Ticket WS13-T3

- Title: Add acknowledgement text capture and immutable storage.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 210 minutes.
- Review estimate: 30 minutes.
- Files: models, service layer, tests.
- Dependencies: WS5-T4.
- Implementation steps:
  - Store the exact acknowledgement text shown to the analyst.
  - Store acknowledgement timestamp and actor.
  - Include acknowledgement hash in provenance.
- Acceptance criteria:
  - Sensitive run acknowledgement is auditable.

### WS13 Ticket WS13-T4

- Title: Add disclosure bundle safety checklist enforcement.
- Primary owner: junior backend engineer.
- Reviewer: security lead.
- Estimate: 240 minutes.
- Review estimate: 30 minutes.
- Files: disclosure service, tests.
- Dependencies: WS10-T3, WS10-T5.
- Implementation steps:
  - Require review state for included artifacts.
  - Warn on raw PCAP inclusion.
  - Warn on sensitive logs.
  - Require explicit confirmation for externally exportable bundles.
- Acceptance criteria:
  - Unsafe exports are harder to create accidentally.

### WS13 Ticket WS13-T5

- Title: Add operator-facing safety warnings in the UI.
- Primary owner: junior frontend engineer.
- Reviewer: security lead.
- Estimate: 180 minutes.
- Review estimate: 20 minutes.
- Files: run console, recipe builder, disclosure page.
- Dependencies: WS11-T3, WS11-T6, WS10-T6.
- Implementation steps:
  - Add sensitive run warning banners.
  - Add export caution banners.
  - Add policy mismatch warnings.
  - Add collector compatibility warnings.
- Acceptance criteria:
  - Safety posture is visible in workflow, not just docs.

## 35. WS14 Overview

- Objective: complete the PRD’s `v1.1` and `v1.2` expansion layers.
- Pod owner: shared between Pods A, B, E, F, and G.
- Supporting pods: Pod H.
- Blocking risk: medium.
- Parallelization impact: high.
- Must start by: Week 13.
- Must reach useful completion by: Week 18.

### WS14 Scope

- richer SBOM import
- package-to-service mapping
- service dependency overlays
- VEX authoring suggestions
- confidence scoring for applicability
- disclosure and bounty bundle quality
- redaction polishing
- reproducibility appendix polishing

### WS14 Ticket WS14-T1

- Title: Improve package and version normalization quality.
- Primary owner: junior backend engineer.
- Reviewer: Pod A lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: import service, normalization modules, tests.
- Dependencies: WS1-T2, WS1-T3, WS2-T5.
- Implementation steps:
  - Normalize vendor aliases.
  - Normalize product aliases.
  - Normalize package ecosystems.
  - Normalize version range comparison helpers.
  - Add test fixtures for messy real-world version strings.
- Acceptance criteria:
  - Applicability scoring improves on imperfect source data.

### WS14 Ticket WS14-T2

- Title: Add service dependency graph overlay to Sheshnaag views.
- Primary owner: junior backend engineer.
- Reviewer: Pod B lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: graph service, Sheshnaag API enrichment, frontend bindings.
- Dependencies: existing graph foundation, WS2-T5.
- Implementation steps:
  - Expose service dependency context in candidate and run views.
  - Link package data to services.
  - Highlight exposure and blast-radius hints.
- Acceptance criteria:
  - Candidates and runs show environment-aware service context.

### WS14 Ticket WS14-T3

- Title: Add VEX authoring assistant workflow.
- Primary owner: junior backend engineer.
- Reviewer: Pod E lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: artifact generator, import service, routes, tests.
- Dependencies: WS8-T7.
- Implementation steps:
  - Convert suggestion outputs into editable draft statements.
  - Allow analyst adjustment before export.
  - Keep provenance to evidence and run IDs.
- Acceptance criteria:
  - Analysts can turn findings into VEX-oriented outputs faster.

### WS14 Ticket WS14-T4

- Title: Add confidence scoring for affected versus not affected classification.
- Primary owner: junior backend engineer.
- Reviewer: Pod B lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: scoring service, tests.
- Dependencies: WS2-T5, WS14-T1.
- Implementation steps:
  - Combine SBOM match quality.
  - Combine VEX state clarity.
  - Combine evidence signal quality.
  - Combine service exposure relevance.
  - Expose confidence in the UI and exports.
- Acceptance criteria:
  - Applicability claims have explicit confidence ratings.

### WS14 Ticket WS14-T5

- Title: Improve disclosure bundle quality for vendor and bounty use cases.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: disclosure templates, export service, tests.
- Dependencies: WS10-T2 through WS10-T5.
- Implementation steps:
  - Improve executive summary quality.
  - Improve impact statement formatting.
  - Improve evidence appendix organization.
  - Improve reproduction section clarity.
  - Improve remediation recommendation wording.
- Acceptance criteria:
  - Bundles are submission-quality, not internal-debug quality.

### WS14 Ticket WS14-T6

- Title: Build v1.1 and v1.2 frontend polish work.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: multiple pages and components.
- Dependencies: WS14-T2 through WS14-T5.
- Implementation steps:
  - Add service context views.
  - Add VEX suggestion editor.
  - Add confidence badges.
  - Add richer disclosure template previews.
- Acceptance criteria:
  - v1.1 and v1.2 capabilities are visible and usable.

## 36. WS15 Overview

- Objective: complete the PRD’s `v1.3`, `v1.4`, and `v2.0` path.
- Pod owner: shared program ownership.
- Supporting pods: all.
- Blocking risk: medium.
- Parallelization impact: high.
- Must start by: Week 17.
- Must continue through: Week 24 and beyond.

### WS15 Scope

- peer review queue
- artifact approval workflow
- dispute and correction history
- contribution weighting polish
- differential validation
- paired-run comparison
- recipe libraries
- reusable evidence patterns
- cross-run clustering
- richer ledger analytics

### WS15 Ticket WS15-T1

- Title: Build peer review queue backend.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: review models, services, routes, tests.
- Dependencies: WS8-T8, WS9-T6.
- Implementation steps:
  - Add queue states for pending review.
  - Add assignee support.
  - Add aging and priority fields.
  - Add list and detail routes.
- Acceptance criteria:
  - Team leads can manage review workload explicitly.

### WS15 Ticket WS15-T2

- Title: Build dispute and correction history model.
- Primary owner: junior backend engineer.
- Reviewer: Pod F lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: models, services, tests.
- Dependencies: WS15-T1.
- Implementation steps:
  - Add correction records for artifacts and disclosures.
  - Add dispute states.
  - Link corrections to superseding revisions.
  - Preserve immutable history.
- Acceptance criteria:
  - Review reversals and corrections are auditable.

### WS15 Ticket WS15-T3

- Title: Build paired-run comparison backend.
- Primary owner: junior backend engineer.
- Reviewer: Pod C lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: run services, comparison services, tests.
- Dependencies: WS4-T3, WS6-T10.
- Implementation steps:
  - Define paired-run entity or comparison payload.
  - Compare process trees.
  - Compare file diffs.
  - Compare package diffs.
  - Compare network metadata.
  - Summarize changed findings.
- Acceptance criteria:
  - Differential validation exists as a real backend feature.

### WS15 Ticket WS15-T4

- Title: Build paired-run comparison frontend.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 420 minutes.
- Review estimate: 60 minutes.
- Files: comparison page, components, bindings.
- Dependencies: WS15-T3.
- Implementation steps:
  - Add before versus after selector.
  - Add diff cards by evidence type.
  - Highlight regressions and fixes.
  - Show VEX confidence implications.
- Acceptance criteria:
  - Differential validation is usable visually.

### WS15 Ticket WS15-T5

- Title: Build recipe library and reuse catalog.
- Primary owner: junior backend engineer.
- Reviewer: Pod C lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: recipe services, routes, frontend bindings, tests.
- Dependencies: WS5 completion.
- Implementation steps:
  - Add publishable recipe templates.
  - Add tags and search.
  - Add clone-from-template flow.
  - Add attribution tracking.
- Acceptance criteria:
  - Teams can reuse recipes without copy-paste drift.

### WS15 Ticket WS15-T6

- Title: Build reusable evidence pattern library.
- Primary owner: junior backend engineer.
- Reviewer: Pod E lead.
- Estimate: 300 minutes.
- Review estimate: 45 minutes.
- Files: artifact and evidence modules, tests.
- Dependencies: WS8 completion.
- Implementation steps:
  - Store evidence patterns extracted from successful runs.
  - Tag them by product, package, or CVE family.
  - Reuse them in future rule generation assistance.
- Acceptance criteria:
  - The platform compounds in value across runs.

### WS15 Ticket WS15-T7

- Title: Build cross-run clustering for similar findings.
- Primary owner: junior backend engineer.
- Reviewer: Pod E lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: clustering service, tests.
- Dependencies: WS15-T6.
- Implementation steps:
  - Group similar evidence patterns.
  - Group similar artifacts.
  - Group similar runtime findings.
  - Expose cluster summaries.
- Acceptance criteria:
  - The platform can identify repeated patterns across runs.

### WS15 Ticket WS15-T8

- Title: Build richer ledger analytics and lead dashboards.
- Primary owner: junior frontend engineer.
- Reviewer: Pod G lead.
- Estimate: 360 minutes.
- Review estimate: 45 minutes.
- Files: analyst ledger page, reports page, bindings.
- Dependencies: WS9-T8, WS15-T1, WS15-T2.
- Implementation steps:
  - Show contribution trends.
  - Show review participation.
  - Show artifact acceptance rates.
  - Show disclosure conversion rates.
- Acceptance criteria:
  - Research leads can measure throughput and quality.

## 37. Weekly Execution Plan

### Week 0

- Monday 09:00 to 10:00: kickoff meeting, review PRD scope and safety posture.
- Monday 10:00 to 11:30: issue creation based on WS0 backlog.
- Monday 11:30 to 12:00: break.
- Monday 12:00 to 13:00: file ownership walkthrough.
- Monday 14:00 to 15:00: contract freeze meeting.
- Monday 15:00 to 17:00: WS0-T1 execution.
- Tuesday 09:00 to 11:00: WS0-T2 execution.
- Tuesday 11:00 to 13:00: WS0-T3 execution.
- Tuesday 14:00 to 16:30: WS0-T4 execution.
- Tuesday 16:30 to 17:00: issue dependency cleanup.
- Wednesday 09:00 to 12:00: WS0-T5 execution.
- Wednesday 13:00 to 15:00: WS0-T6 execution.
- Wednesday 15:00 to 17:00: review and doc revisions.
- Thursday 09:00 to 12:00: baseline branch and env cleanup.
- Thursday 13:00 to 15:00: test suite scaffolding prep.
- Thursday 15:00 to 17:00: pod handoff meeting.
- Friday 09:00 to 10:00: sprint readiness review.
- Friday 10:00 to 12:00: backlog split by pod.
- Friday 13:00 to 15:00: architecture Q and A.
- Friday 15:00 to 17:00: risk register update.

### Week 1

- Pod A starts WS1-T1 and WS1-T4.
- Pod B starts WS2-T1 and WS2-T2.
- Pod H starts WS12-T1 and WS12-T2.
- Monday 09:00 to 09:30: daily standup plus dependency check.
- Monday 09:30 to 12:30: WS1-T1 coding block.
- Monday 13:30 to 16:30: WS2-T1 coding block.
- Monday 16:30 to 17:00: review request prep.
- Tuesday 09:00 to 12:00: WS1-T4 coding block.
- Tuesday 13:00 to 15:30: WS2-T2 coding block.
- Tuesday 15:30 to 17:00: test drafting.
- Wednesday 09:00 to 10:00: shared scoring factor review.
- Wednesday 10:00 to 12:30: WS1-T1 finalization.
- Wednesday 13:30 to 16:30: WS2-T1 tests.
- Thursday 09:00 to 12:00: WS12-T1 suite structuring.
- Thursday 13:00 to 16:00: WS12-T2 smoke harness setup.
- Friday 09:00 to 11:00: PR review cycle.
- Friday 11:00 to 13:00: fix follow-ups.
- Friday 14:00 to 16:00: demo of refactored connector abstraction and expanded scoring factors.
- Friday 16:00 to 17:00: retrospective.

### Week 2

- Pod A starts WS1-T2 and WS1-T3.
- Pod C starts WS4-T1 and WS4-T5.
- Pod H starts WS13-T1.
- Monday 09:00 to 09:30: dependency standup.
- Monday 09:30 to 12:30: OSV connector coding.
- Monday 13:30 to 16:30: provider lifecycle interface coding.
- Tuesday 09:00 to 12:00: GHSA connector coding.
- Tuesday 13:00 to 16:00: template catalog coding.
- Wednesday 09:00 to 10:00: ingestion normalization review.
- Wednesday 10:00 to 12:30: safety audit kickoff.
- Wednesday 13:30 to 16:30: connector tests.
- Thursday 09:00 to 12:00: provider contract tests.
- Thursday 13:00 to 16:00: demo of template catalog and connector registry.
- Friday 09:00 to 12:00: review cycle.
- Friday 13:00 to 15:00: backlog adjustments.
- Friday 15:00 to 17:00: risk review around live execution work.

### Week 3

- Pod B starts WS2-T3 and WS2-T4.
- Pod G starts WS3-T1 and WS3-T2.
- Pod C starts WS4-T2.
- Monday 09:00 to 09:30: standup.
- Monday 09:30 to 12:30: candidate action API coding.
- Monday 13:30 to 16:30: frontend route map and API binding coding.
- Tuesday 09:00 to 12:00: real Docker execution coding.
- Tuesday 13:00 to 16:00: candidate filter query coding.
- Wednesday 09:00 to 10:30: contract review between Pods B and G.
- Wednesday 10:30 to 12:30: frontend route fixes.
- Wednesday 13:30 to 16:30: Docker execution tests.
- Thursday 09:00 to 12:00: candidate API tests.
- Thursday 13:00 to 16:00: frontend binding tests.
- Friday 09:00 to 11:00: demo of candidate actions and operator route skeleton.
- Friday 11:00 to 13:00: live execution safety review.
- Friday 14:00 to 17:00: bug fixes.

### Week 4

- Pod D starts WS6-T1, WS6-T2, and WS6-T3.
- Pod A finishes WS1-T5 through WS1-T8.
- Pod G starts WS3-T3 and WS3-T4.
- Monday 09:00 to 09:30: standup.
- Monday 09:30 to 12:30: collector framework refactor.
- Monday 13:30 to 16:30: candidate queue UI coding.
- Tuesday 09:00 to 12:00: process collector coding.
- Tuesday 13:00 to 16:00: package diff collector coding.
- Wednesday 09:00 to 10:00: evidence envelope design review.
- Wednesday 10:00 to 12:30: intel overview freshness enrichment.
- Wednesday 13:30 to 16:30: candidate detail panel coding.
- Thursday 09:00 to 12:00: collector tests.
- Thursday 13:00 to 16:00: queue UI tests.
- Friday 09:00 to 11:00: demo of real candidate queue and early collectors.
- Friday 11:00 to 13:00: review cycle.
- Friday 14:00 to 17:00: fixes and docs.

### Week 5

- Pod C starts WS5-T1 and WS5-T2.
- Pod D starts WS6-T4 and WS6-T5.
- Pod G starts WS5-T5 and WS5-T6.
- Monday 09:00 to 09:30: standup.
- Monday 09:30 to 12:30: recipe schema coding.
- Monday 13:30 to 16:30: file diff collector coding.
- Tuesday 09:00 to 12:00: network metadata collector coding.
- Tuesday 13:00 to 16:00: recipe builder API bindings.
- Wednesday 09:00 to 10:00: schema review.
- Wednesday 10:00 to 12:30: linting logic coding.
- Wednesday 13:30 to 16:30: recipe builder shell coding.
- Thursday 09:00 to 12:00: collector tests.
- Thursday 13:00 to 16:00: recipe builder tests.
- Friday 09:00 to 11:00: demo of recipe builder shell and real network evidence.
- Friday 11:00 to 13:00: review cycle.
- Friday 14:00 to 17:00: bug fixes.

### Week 6

- Pod C starts WS4-T3 and WS4-T4.
- Pod D starts WS6-T6 and WS6-T7.
- Pod G starts WS11-T1 and WS11-T3.
- Monday 09:00 to 09:30: standup.
- Monday 09:30 to 12:30: run lifecycle API expansion.
- Monday 13:30 to 16:30: service log collector coding.
- Tuesday 09:00 to 12:00: osquery collector integration.
- Tuesday 13:00 to 16:00: run console design system work.
- Wednesday 09:00 to 10:00: live run observability review.
- Wednesday 10:00 to 12:30: guest health logic coding.
- Wednesday 13:30 to 16:30: run console page coding.
- Thursday 09:00 to 12:00: lifecycle tests.
- Thursday 13:00 to 16:00: frontend run console tests.
- Friday 09:00 to 11:00: demo of lifecycle control and run console.
- Friday 11:00 to 13:00: review cycle.
- Friday 14:00 to 17:00: bug fixes.

### Week 7

- Pod D starts WS7-T1 through WS7-T3.
- Pod E starts WS8-T1 and WS8-T2.
- Pod F starts WS9-T1 and WS9-T2.
- Monday 09:00 to 09:30: standup.
- Monday 09:30 to 12:30: runtime envelope design.
- Monday 13:30 to 16:30: artifact extractor design.
- Tuesday 09:00 to 12:00: Tracee integration coding.
- Tuesday 13:00 to 16:00: attestation payload schema coding.
- Wednesday 09:00 to 10:30: cross-pod telemetry and artifact contract review.
- Wednesday 10:30 to 12:30: Sigma generator improvements.
- Wednesday 13:30 to 16:30: pluggable signing backend coding.
- Thursday 09:00 to 12:00: Falco integration coding.
- Thursday 13:00 to 16:00: tests for envelope and attestation.
- Friday 09:00 to 11:00: demo of normalized telemetry events and upgraded attestations.
- Friday 11:00 to 13:00: review cycle.
- Friday 14:00 to 17:00: bug fixes.

### Week 8

- Pod D starts WS6-T8 through WS6-T10.
- Pod E starts WS8-T3 through WS8-T5.
- Pod F starts WS10-T1 and WS10-T2.
- Monday 09:00 to 09:30: standup.
- Monday 09:30 to 12:30: PCAP collector coding.
- Monday 13:30 to 16:30: Falco rule generation improvements.
- Tuesday 09:00 to 12:00: evidence storage metadata coding.
- Tuesday 13:00 to 16:00: Suricata generation coding.
- Wednesday 09:00 to 10:00: export package format review.
- Wednesday 10:00 to 12:30: YARA generation coding.
- Wednesday 13:30 to 16:30: evidence timeline payload coding.
- Thursday 09:00 to 12:00: bundle template coding.
- Thursday 13:00 to 16:00: tests across evidence and artifacts.
- Friday 09:00 to 11:00: demo of richer evidence plus artifact outputs.
- Friday 11:00 to 13:00: review cycle.
- Friday 14:00 to 17:00: fixes.

### Week 9

- Pod E starts WS8-T6 through WS8-T9.
- Pod F starts WS9-T3 through WS9-T6.
- Pod G starts WS11-T4 and WS11-T5.
- Monday 09:00 to 09:30: standup.
- Monday 09:30 to 12:30: mitigation v2 coding.
- Monday 13:30 to 16:30: provenance linkage coding.
- Tuesday 09:00 to 12:00: OpenVEX suggestions coding.
- Tuesday 13:00 to 16:00: evidence explorer coding.
- Wednesday 09:00 to 10:00: provenance center payload review.
- Wednesday 10:00 to 12:30: artifact review state machine coding.
- Wednesday 13:30 to 16:30: ledger scoring expansion coding.
- Thursday 09:00 to 12:00: feedback capture coding.
- Thursday 13:00 to 16:00: explorer deep-link flow coding.
- Friday 09:00 to 11:00: demo of provenance linkage and evidence explorer.
- Friday 11:00 to 13:00: review cycle.
- Friday 14:00 to 17:00: fixes.

### Week 10

- Pod F starts WS10-T3 through WS10-T5.
- Pod G starts WS8-T10, WS9-T7, and WS9-T8.
- Pod H starts cross-feature integration tests.
- Monday 09:00 to 09:30: standup.
- Monday 09:30 to 12:30: evidence selection and redaction backend coding.
- Monday 13:30 to 16:30: artifact forge frontend coding.
- Tuesday 09:00 to 12:00: reproduction steps generator coding.
- Tuesday 13:00 to 16:00: provenance center frontend coding.
- Wednesday 09:00 to 10:00: disclosure bundle UX review.
- Wednesday 10:00 to 12:30: archive export builder coding.
- Wednesday 13:30 to 16:30: analyst ledger frontend coding.
- Thursday 09:00 to 12:00: integration test writing.
- Thursday 13:00 to 16:00: frontend smoke test updates.
- Friday 09:00 to 11:00: demo of export-ready bundles and provenance center.
- Friday 11:00 to 13:00: review cycle.
- Friday 14:00 to 17:00: fixes.

### Week 11

- Pod G completes WS10-T6 and WS11-T6 through WS11-T8.
- Pod H runs full release rehearsal.
- Monday 09:00 to 09:30: standup.
- Monday 09:30 to 12:30: disclosure bundle frontend coding.
- Monday 13:30 to 16:30: nav and resilience UX coding.
- Tuesday 09:00 to 12:00: integration test cleanup.
- Tuesday 13:00 to 16:00: release rehearsal script coding.
- Wednesday 09:00 to 12:00: full-system bug bash.
- Wednesday 13:00 to 16:00: triage and fix session.
- Thursday 09:00 to 12:00: second bug bash.
- Thursday 13:00 to 16:00: docs polish and onboarding notes.
- Friday 09:00 to 11:00: v1.0 dress rehearsal demo.
- Friday 11:00 to 13:00: go or no-go review.
- Friday 14:00 to 17:00: release candidate fixes.

### Week 12

- Monday 09:00 to 12:00: release candidate validation.
- Monday 13:00 to 16:00: final smoke tests.
- Tuesday 09:00 to 11:00: release sign-off.
- Tuesday 11:00 to 13:00: tag, package, and internal announcement.
- Tuesday 14:00 to 17:00: post-release verification.
- Wednesday 09:00 to 10:00: release retrospective.
- Wednesday 10:00 to 12:00: backlog re-baseline for v1.1 and v1.2.
- Wednesday 13:00 to 17:00: buffer.
- Thursday and Friday: reserved for hotfixes only.

### Week 13

- Start WS14-T1 and WS14-T2.
- Allocate 60 percent of capacity to normalization depth.
- Allocate 40 percent of capacity to service dependency visualization.
- Run one design review mid-week.
- End the week with an applicability confidence demo.

### Week 14

- Start WS14-T3 and WS14-T4.
- Allocate 50 percent of capacity to VEX authoring assistance.
- Allocate 50 percent of capacity to confidence scoring.
- End the week with a VEX suggestion walkthrough.

### Week 15

- Start WS14-T5 and WS14-T6.
- Allocate 60 percent of capacity to disclosure bundle quality.
- Allocate 40 percent of capacity to frontend polish.
- End the week with a vendor-ready and bounty-ready bundle demo.

### Week 16

- Run v1.1 and v1.2 integration hardening.
- Expand fixture packs.
- Run dedicated reviewer QA on bundle quality and applicability confidence.
- Close only defects and docs gaps.

### Week 17

- Start WS15-T1 and WS15-T2.
- Focus on peer review queue and correction history.
- Keep UI shell simple but functional.
- End the week with a review workflow demo.

### Week 18

- Start WS15-T3 and WS15-T4.
- Focus on differential validation backend and comparison UI.
- End the week with a before-versus-after run demo.

### Week 19

- Start WS15-T5 and WS15-T6.
- Focus on recipe library and evidence pattern library.
- End the week with a reuse and clone workflow demo.

### Week 20

- Start WS15-T7 and WS15-T8.
- Focus on cross-run clustering and richer analytics.
- End the week with lead dashboard demo.

### Week 21

- Stabilization week for v1.3 and v1.4.
- Fix review workflow defects.
- Fix paired-run comparison defects.
- Improve library search and tagging.

### Week 22

- Platform readiness for `v2.0` foundations.
- Revisit scaling assumptions.
- Revisit analytics schema.
- Revisit export API contracts.

### Week 23

- Hardening and backlog reduction.
- Prioritize data quality and query performance.
- Add any missing docs and operational runbooks.

### Week 24

- v2.0 foundation review.
- Decide next-quarter focus.
- Archive completed milestones and reset the roadmap board.

## 38. Junior Developer Assignment Matrix

- Junior backend engineer 1:
  - WS1 connectors
  - WS2 scoring expansion
  - WS6 process and package collectors
- Junior backend engineer 2:
  - WS4 provider lifecycle
  - WS5 recipe schema and linting
  - WS10 export implementation
- Junior backend engineer 3:
  - WS6 network and service log collectors
  - WS7 runtime telemetry normalization
  - WS8 artifact extractors
- Junior frontend engineer 1:
  - WS3 candidate queue
  - WS11 intel dashboard
  - WS11 navigation and resilience UX
- Junior frontend engineer 2:
  - WS5 recipe builder
  - WS11 run console
  - WS11 evidence explorer
- Junior frontend engineer 3:
  - WS8 artifact forge
  - WS9 provenance center
  - WS10 disclosure bundles
- Junior QA engineer 1:
  - WS12 suite structure
  - WS12 smoke commands
  - WS6 and WS7 test matrices
- Junior QA engineer 2:
  - candidate, recipe, and run integration tests
  - provenance and disclosure integration tests
  - release rehearsal support

## 39. Required Review Cadence

- Every ticket under 240 minutes gets one review.
- Every ticket over 240 minutes gets one design review and one code review.
- Every schema change gets migration review.
- Every live execution change gets safety review.
- Every export change gets disclosure safety review.
- Every runtime telemetry change gets performance review.

## 40. Daily Team Rhythm

- 09:00 to 09:15: standup.
- 09:15 to 09:30: dependency escalation.
- 09:30 to 12:00: maker block one.
- 12:00 to 13:00: break.
- 13:00 to 15:30: maker block two.
- 15:30 to 16:30: review and test block.
- 16:30 to 17:00: notes and next-step prep.

## 41. PR Template Requirements

- What gap from the PRD does this PR close.
- Which workstream and ticket does it implement.
- What files are owned by this PR.
- What safety assumptions changed.
- What tests were added.
- What screenshots or API examples are included.
- What remains out of scope.

## 42. Demo Requirements Per Milestone

- M1 demo:
  - sync at least one non-NVD source
  - show feed freshness and provenance
- M2 demo:
  - choose a candidate in the UI
  - assign and defer a candidate
- M3 demo:
  - launch a real constrained run
  - stop and destroy it
- M4 demo:
  - inspect real evidence artifacts
- M5 demo:
  - inspect runtime telemetry and findings
- M6 demo:
  - approve a generated artifact
- M7 demo:
  - trace a run to evidence, artifact, and signature
- M8 demo:
  - export and download a bundle
- M9 demo:
  - complete the workflow from UI only
- M10 demo:
  - go from fresh CVE to signed bundle on one workstation

## 43. Final Notes

- The biggest risk to this roadmap is false progress from placeholder implementations.
- The second biggest risk is letting old CVE Threat Radar flows masquerade as Sheshnaag completeness.
- The third biggest risk is junior developers taking on slices that are too wide.
- The way to avoid all three is to keep scope bounded, interfaces explicit, and milestone demos brutally honest.
- If the team follows this roadmap closely, Sheshnaag can move from a promising backend skeleton to a genuinely high-capacity defensive research platform.
