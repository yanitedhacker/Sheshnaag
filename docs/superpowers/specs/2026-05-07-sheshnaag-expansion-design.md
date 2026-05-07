# Sheshnaag Expansion PRD: From V4 Beta to End-to-End Cybersecurity Research Lab

**Status:** Approved (2026-05-07) — execution orchestration plan at `~/.claude/plans/find-the-latest-prd-whimsical-fairy.md`
**Date:** 2026-05-07
**Scope:** Roadmap PRD covering four sequenced milestones (V5 → V6 → V7 → V8)
**Owner:** ArchFit
**Spec history:** Drafted in plan mode at `~/.claude/plans/lets-make-a-project-ethereal-snail.md`; copied here as the durable record after PRD approval.

---

## Context

**Why this change is being made.** Sheshnaag V4 ships as a mature beta of a *defensive-only, single-host, single-operator-or-small-team* vulnerability research lab. All core pillars are wired: real AI provider harness across six families ([app/services/ai_provider_harness.py](app/services/ai_provider_harness.py)), real dynamic analysis on Docker-Kali with egress enforcement ([app/lab/](app/lab/)), capability-policy-gated tool access ([app/services/capability_policy.py](app/services/capability_policy.py)), Merkle-chained audit log, threat-intel fabric (OSV/GHSA/KEV/EPSS/NVD), pgvector knowledge base, autonomous analyst agent ([app/services/autonomous_agent.py](app/services/autonomous_agent.py)), behavior-similarity + variant-diff over pgvector embeddings, NL hunt + scheduled briefs, STIX 2.1 export.

**The gap.** "End-to-end cybersecurity research lab" demands four things V4 does not yet provide:
1. **Team operability** — workflow state machines, RBAC, review queues, SSO, deeper Slack/Linear/JIRA, team analytics.
2. **Full-spectrum capability + Windows targets** — activate the policy hooks that already exist for `red_team_emulation`, `exploit_validation`, `offensive_research`; add a Windows libvirt provider with Sysmon/ETW telemetry.
3. **External output chain** — CVE/CNA coordination, vendor disclosure, public threat intel publishing, academic publication with reproducibility packages and DOIs.
4. **Multi-host scale** — V4's single-host ceiling becomes the bottleneck the moment more than 2-3 detonations or a Windows VM run concurrently.

**Intended outcome.** A 3-15 person research team can take an interesting CVE from the wild all the way to a published artifact (internal rule, vendor-coordinated CVE, public IOC pulse, or DOI'd academic dataset) under signed capability policy, on a worker-pool deployment, with reviewer-in-the-loop AI throughout — without leaving Sheshnaag.

---

## Strategic Decisions (locked)

| Axis | Decision |
|---|---|
| Audience | Small research team (3-15) |
| Posture | Full-spectrum under capability policy (activate offensive hooks, all gated) |
| Targets | Linux (existing) + **Windows libvirt VMs** (new) |
| Orchestration | **Worker pool over LAN** (control plane + N sandbox workers, mTLS, no K8s) |
| AI ceiling | Reviewer-in-the-loop status quo + polish (multi-agent UI, grounding, MLX-default) |
| End-of-funnel | All four: internal artifacts, CVE coordination, public intel, academic publication |
| Structure | Sequential milestones V5→V6→V7→V8, each independently shippable with kill-criteria gates |

Out of scope for this PRD: Kubernetes/Nomad orchestration, multi-tenant SaaS federation, mobile detonation (Android/iOS), firmware/UEFI analysis, cloud workload sandboxes, hardware side-channel research. These remain V9+ deferrals.

---

## Guiding Principles (load-bearing across all milestones)

1. **Capability policy is the chokepoint.** Every new offensive feature flows through [app/services/capability_policy.py](app/services/capability_policy.py) + signed authorization artifacts. No bypasses.
2. **Reviewer-in-the-loop is non-negotiable.** AI proposes; humans approve before any signed export, external action, or destructive operation.
3. **Workers are cattle.** Sandbox workers reimage cleanly; no long-lived state on workers; signing is centralized on the control plane.
4. **Reproducibility is a first-class output.** Every shippable artifact carries enough context that another lab can re-run the analysis.
5. **No premature multi-tenancy.** The existing `tenants` namespace stays for scoping but no cross-tenant federation work happens.
6. **Each milestone ships standalone.** Kill-criteria gates between V5/V6/V7/V8 — if a milestone fails its gate, expansion stops there with a working product.

---

## Cross-Cutting Changes

These touch all four milestones and need design once:

- **New `roles` + `permissions` tables.** Roles: `analyst`, `senior_analyst`, `reviewer`, `lab_lead`, `read_only`. Permissions map to capability scope modifiers. Migration in `app/migrations/`. Existing `tenants` namespace retained.
- **Case lifecycle state machine.** New enum `case_lifecycle_state` with transitions `triage → analysis → review → ready_to_ship → shipped → archived`. Implemented in new `app/services/case_workflow.py`. Persisted on existing case model.
- **`artifact_publication` table.** Tracks every external destination an artifact has been pushed to (CVE, MISP, OTX, Zenodo, blog), with signing metadata + revocation control. New migration + new `app/services/publication_ledger.py`.
- **Capability policy extensions.** New named capabilities added to [app/services/capability_policy.py](app/services/capability_policy.py): `cve_coordination`, `vendor_disclosure`, `public_intel_publish`, `dataset_publish`. Existing seven capabilities retained.
- **Frontend roles & review layer.** Existing 35 operator pages get a permission-gated wrapper; new `RolesAndReview` slice in `frontend/src/`. No URL routes change; behavior of inline actions does.
- **Worker contract.** New `app/services/worker_pool.py` (control plane) + new `app/workers/sandbox_agent.py` (worker side) defining the mTLS bootstrap + Redis-Streams job pull + signed-artifact return.

---

## V5 — "Team Lab" (Foundation)

**Goal:** Make Sheshnaag operable by a 3-15 person team across a worker-pool deployment.
**Estimated duration:** 3-4 months.

### Capability list

1. **Worker pool over LAN.**
   - Control plane = existing app on one host.
   - N sandbox workers (Linux only in V5) join via mTLS bootstrap (worker generates CSR, control plane signs).
   - Workers pull jobs from existing Redis Streams bus; return telemetry + artifacts as signed payloads.
   - Worker registry UI in frontend (online/offline, capability flags, last-heartbeat, drain mode).
   - Critical files: new `app/services/worker_pool.py`, new `app/workers/sandbox_agent.py`, new `app/api/routes/workers.py`, new `frontend/src/pages/WorkerFleetPage.tsx`. Reuse: existing `app/workers/` queue patterns, existing Redis Streams plumbing.

2. **Team workflow.**
   - Case lifecycle state machine (transitions defined in cross-cutting section).
   - Per-state review queues, per-role review queues.
   - Custom case fields (key/value pairs, schema-validated; no full custom schema engine).
   - Critical files: new `app/services/case_workflow.py`, extend existing case model in `app/models/`, new `frontend/src/pages/ReviewQueuePage.tsx`. Reuse: existing case management + review queue scaffolding (V4 already has a basic review queue).

3. **Roles & permissions.**
   - Five roles, mapping to capability scope modifiers (e.g., `analyst` cannot trigger `external_disclosure` even if capability is unlocked).
   - Critical files: new `app/services/rbac.py`, new migrations for `roles`/`permissions` tables, integrate with existing JWT in `app/core/security/`.

4. **OIDC SSO.**
   - Lightweight: support Authentik / Keycloak / Auth0 via standard OIDC.
   - User provisioning on first login (just-in-time), role assignment by claim mapping.
   - Critical files: new `app/api/routes/auth_oidc.py`, extend `app/core/security/`. Existing JWT path remains for service-to-service.

5. **Slack / Linear / JIRA depth.**
   - V4 ships outbound notifications; V5 adds inbound: status sync, mention-based actions, review approvals from the chat surface.
   - Critical files: new `app/services/integrations/{slack,linear,jira}_inbound.py`. Reuse: existing webhook handlers + outbound notifiers.

6. **Team analytics dashboard.**
   - Mean-time-to-rule, review latency, ATT&CK coverage drift over time, per-analyst capability-usage histogram, queue-aging heatmap.
   - Critical files: new `app/services/team_analytics.py`, new `frontend/src/pages/TeamAnalyticsPage.tsx`. Reuse: existing audit log + AI session tables as data sources.

### V5 kill-criteria gate

Before V6 work starts, all of the following must hold on a 3-node test deployment:
- Worker pool sustains 5 concurrent detonations with sub-second job dispatch latency.
- mTLS bootstrap survives a worker reimage without manual intervention.
- OIDC login → role-gated dashboard works end-to-end for at least two IdPs.
- Case lifecycle state machine has a passing red-team test (no transition can be made by a role without permission).
- Team analytics dashboard renders correctly with ≥1000 cases of synthetic data.

---

## V6 — "Full-Spectrum + Windows"

**Goal:** Activate full capability surface (offensive hooks the policy framework already names) and add Windows targets.
**Estimated duration:** 4-5 months.

### Capability list

1. **Windows libvirt provider.**
   - New sandbox provider in `app/lab/providers/libvirt_provider.py` (parallel to existing Docker provider).
   - Snapshot/revert via libvirt domain snapshots.
   - Image building pipeline: Packer-built golden images for Windows 10/11 + Server 2019/2022 with Sysmon + Velociraptor agents pre-installed.
   - Worker capability flag `windows-vm` advertised by workers with libvirt + KVM available.
   - Telemetry: Sysmon (full ruleset), ETW providers via Microsoft-Windows-Threat-Intelligence + Microsoft-Windows-Kernel-Process, optional Velociraptor artifacts.
   - Memory analysis: Volatility 3 windows profiles, MemProcFS optional.
   - Critical files: new `app/lab/providers/libvirt_provider.py`, new `app/lab/collectors/sysmon.py`, new `app/lab/collectors/etw.py`, extend recipe schema in [app/services/recipe_schema.py](app/services/recipe_schema.py). Reuse: existing Docker provider as architectural template, existing snapshot/revert orchestration.

2. **Activate `red_team_emulation` (purple team).**
   - Atomic Red Team test runner integrated as a recipe step.
   - Caldera C2 server can run lab-internal only (egress hard-locked) for chained ATT&CK technique replay.
   - Replay produces a coverage gap report against the lab's existing detection corpus (Sigma + YARA artifact stores).
   - Critical files: new `app/services/purple_team_service.py`, new `app/lab/redteam/atomic_runner.py`, new `app/lab/redteam/caldera_adapter.py`, new `frontend/src/pages/PurpleTeamPage.tsx`.

3. **Activate `exploit_validation`.**
   - Harness fetches PoC code from authorized sources (ExploitDB, Metasploit modules) under signed authorization that names CVE + target image + scope.
   - Runs PoC in scoped sandbox against a vulnerable target image; captures exploitation evidence + patch effectiveness across patched/unpatched pair.
   - Validation report carries signed manifest (target image digest, PoC source digest, evidence digests).
   - Critical files: new `app/services/exploit_validator.py`, new `app/lab/exploits/poc_fetcher.py`, new migration for `exploit_validation_runs` table.

4. **Activate `offensive_research`.**
   - Operator-driven exploit development workflow strictly inside the lab.
   - Fuzzing: AFL++ + libfuzzer harnesses, persistent corpus storage, crash deduplication.
   - Debugger orchestration: gdb (Linux), WinDbg (Windows), pwntools integration, optional Triton symbolic execution.
   - Crash triage with AI-assisted classification (exploitable/not exploitable/needs review).
   - Hard-scoped to operator-owned or explicitly authorized targets via signed scope artifact.
   - Critical files: new `app/lab/research/fuzzing.py`, new `app/lab/research/debugger.py`, new `app/lab/research/crash_triage.py`, new `frontend/src/pages/ResearchWorkbenchPage.tsx`.

5. **Authorization workflow upgrade.**
   - Multi-reviewer signing for offensive capabilities (V4 capability policy supports multi-reviewer schema; V6 wires the UI flow).
   - Reviewer roster + quorum requirements per capability (e.g., `offensive_research` requires lab_lead + senior_analyst).
   - Audit log already covers this; UI surface in frontend `AuthorizationCenter` (already exists; extend for quorum flow).
   - Critical files: extend [app/services/capability_policy.py](app/services/capability_policy.py), extend frontend `AuthorizationCenter`.

### V6 kill-criteria gate

- All three offensive capabilities pass an external pentest of the policy chokepoint: no scope escapes, no exfil of unauthorized targets, audit log unforgeable.
- Windows VM detonation completes end-to-end (specimen → telemetry → artifacts → signed bundle) with parity-of-evidence to Linux Docker baseline.
- Atomic Red Team replay covers ≥ 80 ATT&CK techniques mapped against detection corpus.
- Exploit validator produces valid attestation for at least one real CVE with vulnerable + patched image pair.
- Multi-reviewer authorization flow has zero single-reviewer escape paths in penetration testing.

---

## V7 — "Output Chain"

**Goal:** Everything Sheshnaag produces can be shipped externally — internal, vendor-coordinated, public, or academic.
**Estimated duration:** 3-4 months.

### Capability list

1. **CVE / CNA coordination workflow.**
   - State machine: `discovered → vendor_notified → embargo_active → embargo_expiring → published → revoked?`.
   - CNA submission via MITRE CNA API + GitHub-as-CNA path.
   - Vendor contact CRM: lightweight (contacts + threads + last-touch + PGP keys), not a full CRM rebuild.
   - Embargo timer with automated reminders to assigned reviewer.
   - Critical files: new `app/services/cve_coordination.py`, new migration for `cve_records` + `vendor_contacts` + `disclosure_threads` tables, new `frontend/src/pages/CveCoordinationPage.tsx`.

2. **Multi-party disclosure bundles.**
   - Existing signed bundle export gains optional co-signer slots (vendor, third-party validator).
   - Cryptographic timestamping via Rekor (already optional in V4; V7 makes it a workflow gate for `vendor_disclosure`).
   - Critical files: extend existing disclosure bundle service in `app/services/`. Reuse: existing cosign/Rekor plumbing.

3. **Public intel publishing.**
   - MISP community publish (existing MISP integration is consumer-side; V7 adds publisher-side).
   - AlienVault OTX pulse export.
   - Blog draft generator: structured Markdown with reproducibility footer (target image digest, recipe digest, evidence digest hashes, citation block).
   - All three gated by `public_intel_publish` capability + reviewer.
   - Critical files: new `app/services/intel_publish.py`, new `app/services/blog_drafter.py`. Reuse: existing MISP/OTX adapters in `app/services/ioc_enrichment.py`.

4. **Academic publication path.**
   - Zenodo upload integration (datasets + reports + DOI assignment).
   - Reproducibility packages: locked Docker images (digest-pinned) + frozen recipes + dataset checksums + CITATION.cff + BibTeX.
   - Optional ORCID linkage for analyst credit.
   - Critical files: new `app/services/reproducibility.py`, new `app/services/zenodo_publisher.py`, new `frontend/src/pages/PublicationsPage.tsx`.

5. **Public artifact registry (`PublicationLedger`).**
   - Lab-internal page listing every artifact published externally with destination, signature, publication timestamp, revocation status.
   - One-click revocation that updates external destination where supported (MISP retraction, Zenodo deprecate, blog edit notice).
   - Critical files: new `frontend/src/pages/PublicationLedger.tsx`, backed by the cross-cutting `artifact_publication` table.

### V7 kill-criteria gate

End-to-end dry run on staging:
- Lab discovers a (synthetic) CVE.
- Coordinates with a (simulated) vendor through the CRM and embargo timer.
- Publishes IOCs to a MISP test community.
- Drops a Zenodo dataset with assigned DOI.
- All steps logged in audit log + PublicationLedger.
- If any step requires manual intervention outside the UI, it must be fixed before V8 starts.

---

## V8 — "AI Lab Polish"

**Goal:** AI in Sheshnaag is faster, cheaper, more grounded, multi-agent — without changing the reviewer-in-the-loop ceiling.
**Estimated duration:** 2-3 months.

### Capability list

1. **Multi-agent collaboration UI.**
   - Show parallel agents (intel-collector, recipe-author, detection-drafter, reviewer-summarizer) on a single case.
   - Trace tree view, branching, interject button (human nudges agent mid-run).
   - Critical files: new `frontend/src/pages/MultiAgentCasePage.tsx`, extend [app/services/ai_agent_loop.py](app/services/ai_agent_loop.py) for multi-agent dispatch.

2. **Grounding upgrades.**
   - Hybrid retrieval (existing BM25 + cosine in [app/services/knowledge_service.py](app/services/knowledge_service.py)) + reranker (BGE-reranker via local MLX).
   - Grounding-coverage scorer (per-claim source coverage check) before AI output is offered to reviewer.
   - Critical files: extend [app/services/knowledge_service.py](app/services/knowledge_service.py), new `app/services/grounding_scorer.py`.

3. **Faster review loops.**
   - One-click approve/reject inline on streaming output.
   - Keyboard shortcuts (j/k navigate, a approve, r reject, e edit-and-approve).
   - Reviewer-quality metrics (consistency, latency, agreement-with-other-reviewers).
   - Reviewer training data export (de-identified) for fine-tuning local models.
   - Critical files: extend frontend AI surfaces, new `app/services/review_metrics.py`.

4. **MLX-local defaults.**
   - Local inference becomes default; cloud providers become opt-in escalation.
   - Cost dashboard showing per-case spend (cloud vs. local).
   - Reasoning model routing (route hard cases to higher-capability cloud only when local confidence < threshold).
   - Critical files: extend [app/services/ai_provider_harness.py](app/services/ai_provider_harness.py), extend `scripts/sheshnaag_local_mlx.py`, new `app/services/inference_router.py`.

### V8 kill-criteria gate

- Median review latency drops 50% vs. V7 baseline on the same 50 reference cases.
- Grounding-coverage scorer agreement with human review ≥ 0.9 on internal eval set.
- Cost-per-case (when local-default) ≤ 25% of V7 baseline cloud-default.
- Multi-agent collaboration UI completes a real case end-to-end without a regression vs. single-agent path.

---

## Critical Files Summary

### Existing files extended (reuse-first)
- [app/services/capability_policy.py](app/services/capability_policy.py) — add 4 new capabilities, multi-reviewer quorum
- [app/services/ai_provider_harness.py](app/services/ai_provider_harness.py) — inference router, cost telemetry
- [app/services/ai_agent_loop.py](app/services/ai_agent_loop.py) — multi-agent dispatch
- [app/services/knowledge_service.py](app/services/knowledge_service.py) — reranker + grounding-coverage
- [app/services/recipe_schema.py](app/services/recipe_schema.py) — Windows + Atomic Red Team + exploit-validator steps
- [app/services/autonomous_agent.py](app/services/autonomous_agent.py) — worker-pool dispatch
- [app/services/ioc_enrichment.py](app/services/ioc_enrichment.py) — publisher-side hooks
- `app/core/security/` — OIDC, RBAC integration
- `app/migrations/` — new tables for roles, lifecycle, publication, CVE coordination

### New top-level modules
- `app/services/worker_pool.py`, `app/workers/sandbox_agent.py` (V5)
- `app/services/case_workflow.py`, `app/services/rbac.py`, `app/services/team_analytics.py` (V5)
- `app/api/routes/auth_oidc.py`, `app/api/routes/workers.py` (V5)
- `app/services/integrations/{slack,linear,jira}_inbound.py` (V5)
- `app/lab/providers/libvirt_provider.py`, `app/lab/collectors/{sysmon,etw}.py` (V6)
- `app/services/purple_team_service.py`, `app/lab/redteam/{atomic_runner,caldera_adapter}.py` (V6)
- `app/services/exploit_validator.py`, `app/lab/exploits/poc_fetcher.py` (V6)
- `app/lab/research/{fuzzing,debugger,crash_triage}.py` (V6)
- `app/services/cve_coordination.py`, `app/services/intel_publish.py`, `app/services/blog_drafter.py` (V7)
- `app/services/reproducibility.py`, `app/services/zenodo_publisher.py`, `app/services/publication_ledger.py` (V7)
- `app/services/grounding_scorer.py`, `app/services/inference_router.py`, `app/services/review_metrics.py` (V8)

### New frontend pages
- `WorkerFleetPage`, `ReviewQueuePage`, `TeamAnalyticsPage` (V5)
- `PurpleTeamPage`, `ResearchWorkbenchPage` (V6)
- `CveCoordinationPage`, `PublicationsPage`, `PublicationLedger` (V7)
- `MultiAgentCasePage` (V8)

---

## Verification

Per-milestone verification follows the same template:

1. **Unit + integration tests** in `tests/v{5..8}/` covering each new service, with the existing pytest harness.
2. **Smoke runbook** in `docs/runbooks/v{5..8}/` documenting the end-to-end dry run for that milestone (Markdown + recorded `asciinema` cast).
3. **Red-team adversary harness** for capability policy (V6+): a CI job that actively tries to escape scope, exfil unauthorized targets, forge audit log entries. Runs on every PR touching `app/services/capability_policy.py` or any offensive feature.
4. **Kill-criteria gate sign-off** before next milestone's planning starts. Lab Lead signs the gate report.
5. **Released changelog + migration guide** per milestone in `docs/migration/v4-to-v5.md`, `v5-to-v6.md`, `v6-to-v7.md`, `v7-to-v8.md`.
6. **Beta partner dogfooding** between gates: at least one real research team runs the new milestone for two weeks before the next plan is finalized.

End-to-end verification of the whole expansion (post-V8):
- A new analyst onboards via OIDC in under 30 minutes.
- A team of three takes a real CVE from discovery to published Zenodo dataset + MISP pulse + vendor-coordinated CVE record without leaving Sheshnaag.
- Local MLX inference handles 80% of cases end-to-end without cloud fallback.
- Capability policy red-team harness has zero successful escapes across all four milestones.

---

## Out of Scope (V9+ deferrals)

These remain explicitly deferred and should not creep into V5-V8 planning:
- Kubernetes / Nomad orchestration (worker pool + LAN is sufficient for the named audience).
- Multi-tenant SaaS federation (single deployment per org).
- Mobile detonation (Android emulator, iOS simulator).
- Firmware / embedded analysis (QEMU-system, FirmAE, Firmadyne).
- Cloud workload sandboxes (LocalStack, ephemeral cloud accounts).
- Hardware side-channel research.
- macOS native detonation (Apple licensing constraints).
- Production-grade SSO/IdP federation beyond OIDC basics (SAML, SCIM provisioning).
- CTF / training mode (could be a sibling product, not a milestone here).

---

## Open Questions / Known Risks

1. **Windows licensing for golden images.** Need a clear licensing posture for redistributable Windows VM images (likely BYOL with a documented build pipeline rather than shipping pre-built images). Resolve in V6 kickoff.
2. **CNA assignment authority.** Sheshnaag-as-CNA is heavyweight. V7 should default to GitHub-as-CNA path and surface MITRE root CNA submission as a manual fallback.
3. **Atomic Red Team licensing/attribution.** ART is MIT but redistribution rules should be checked for embedded use.
4. **Cosign / Rekor public log exposure.** Some organizations may not want CVE-related artifacts on public Rekor. V7 should support a private timestamping authority option.
5. **MLX availability outside Apple Silicon.** V8 "MLX-local defaults" only applies to Apple Silicon hosts; x86 hosts route to Ollama / vLLM. Document this clearly.
6. **Reviewer fatigue at scale.** V8 metrics should explicitly track reviewer fatigue; if it climbs, AI ceiling needs revisiting in a V9 PRD.

---

## Next Steps After PRD Approval

1. Copy this document from the plan file to `docs/superpowers/specs/2026-05-07-sheshnaag-expansion-design.md` and commit.
2. Invoke the `superpowers:writing-plans` skill to produce a detailed V5 implementation plan (V6/V7/V8 plans wait for their respective kickoffs).
3. Set V5 kickoff date and identify worker-pool test deployment hosts.
4. Recruit one beta partner team for V5 dogfooding.
