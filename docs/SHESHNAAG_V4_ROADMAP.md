# Project Sheshnaag — V4 Roadmap

**Status:** Draft (design approved; execution pending)
**Companion docs:** `SHESHNAAG_V4_PRD.md`, `SHESHNAAG_V4_ARCHITECTURE.md`, `SHESHNAAG_V4_CAPABILITY_POLICY.md`, `SHESHNAAG_V4_DEPLOYMENT.md`.

---

## 0. Shape

Eleven phases. Three tracks (Foundations → Operational core → Novel). Target ~29–38 weeks of focused work. Parallelizable at phase level: A must land first; B and C then run in parallel; D/E/F overlap on a partially-landed B/C; G1–G4 run in parallel after F.

```
A  ──▶ B ──┐
           ├─▶ D ─┐
A  ──▶ C ──┤     ├─▶ E ──▶ F ──▶ G1
           └─────┘         │
                           ├──▶ G2
                           ├──▶ G3
                           ├──▶ G4
                           └──▶ G5
```

Each phase has a GSD-compatible shape: discuss → plan → execute → verify. Every phase closes with a VERIFICATION.md, acceptance checklist, and Merkle audit entries where applicable.

---

## Phase A — Foundations (3–4 weeks)

**Goal:** Unblock every downstream pillar. The lab cannot be "serious AI-enabled" until the AI is real, nor "full-spectrum" until the capability policy is in place.

**Deliverables:**
- Rewrite `app/services/ai_provider_harness.py` around native adapters for Anthropic, OpenAI, Gemini, Azure OpenAI, Bedrock (SigV4), and local Ollama/vLLM. Streaming + tool use + prompt caching where available.
- Introduce `app/services/capability_policy.py` + authorization-artifact model + Merkle-chained audit log. Remove `BLOCKED_PROMPT_PATTERNS`.
- Stand up Postgres + pgvector as default DB. Alembic migration. Demote SQLite to dev.
- Stand up MinIO (quarantine + reports) and Redis (Streams for live events + worker queue).
- Upgrade `app/services/knowledge_service.py` to pgvector 1024-dim embeddings, hybrid BM25 + cosine.
- OpenTelemetry instrumentation end-to-end + structured JSON logging.
- Alembic migration for `authorization_artifacts`, `audit_log_entries`, `knowledge_chunk_embeddings`, `ai_agent_steps`.

**Acceptance:**
- Each of the 6 provider families responds non-fallback to `/api/v3/ai/sessions` with streaming tokens.
- Attempting a capability-gated action without an artifact → `403 capability_required`; audit log gains a `deny` entry.
- Issuing + signing an artifact (two reviewers if required) → subsequent call succeeds; audit log gains `issue`, `approve`, `approve`, `exercise` entries.
- `sheshnaag audit verify` exits 0 on a clean chain; tampering detected.
- Knowledge retrieval returns hits with `{chunk_id, sha256, score}` that the UI can render as clickable sources.

**Key files:**
- Modified: `ai_provider_harness.py`, `knowledge_service.py`, `core/database.py`, `core/security.py`.
- New: `ai_adapters/{anthropic,openai,gemini,azure_openai,bedrock,local}.py`, `capability_policy.py`, `ai_tools_registry.py`, `ai_agent_loop.py`.
- Alembic: `v4_a_foundations_*.py`.

---

## Phase B — Real Dynamic Analysis Engine (5–6 weeks)

**Goal:** Make detonation real. No more hardcoded confidence scores.

**Deliverables:**
- Replace synthetic `malware_lab_service.py::materialize_run_outputs` with a launcher dispatcher.
- New launchers: `pe_launcher`, `elf_launcher`, `browser_launcher`, `email_launcher`, `archive_launcher`, `url_launcher` under `app/lab/launchers/`.
- `egress_enforcer.py` — nftables + dnsmasq sinkhole + INetSim / FakeNet-NG fake-internet + iptables NFLOG pcap tap. Kernel-level enforcement.
- `snapshot_manager.py` — libvirt + lima snapshot create / revert.
- `volatility_runner.py` — guest memory capture + Volatility 3 plugins → `BehaviorFinding` rows.
- `zeek_runner.py` — Zeek over captured pcap → `IndicatorArtifact` rows + enriched evidence.
- `ebpf_tracer.py` — Tetragon / Tracee syscall stream → Redis Streams → SSE.
- Remove 5-s / 20-packet cap in `collectors/pcap.py`.

**Acceptance:**
- Benign test specimen (EICAR-class) detonates in a snapshot-backed VM with kernel-enforced egress; pcap > 5 s captured; Volatility plugins produce real output; Zeek logs emitted.
- `BehaviorFinding.confidence` is derived from telemetry. The hardcoded values 0.84, 0.82, 0.88, 0.71 do not appear in the codebase.
- Snapshot revert restores baseline state; a second run produces the same telemetry (deterministic within tolerance).
- Capability `dynamic_detonation` is enforced at launcher entry; `network_egress_open` required to disable sinkhole.

**Key files:**
- Modified: `malware_lab_service.py`, `docker_kali_provider.py`, `lima_provider.py`, `collectors/pcap.py`.
- New: `lab/egress_enforcer.py`, `lab/snapshot_manager.py`, `lab/volatility_runner.py`, `lab/zeek_runner.py`, `lab/ebpf_tracer.py`, `lab/launchers/*.py`.

---

## Phase C — Threat Intel Fabric (3–4 weeks, parallel with B)

**Goal:** Turn the CVE-centric V3 intel stack into a proper intel fabric with IOC pivot.

**Deliverables:**
- Connectors: `misp_connector.py`, `virustotal_connector.py`, `otx_connector.py`, `abusech_connector.py`, `opencti_connector.py`, `mandiant_connector.py`, `shodan_connector.py`.
- `stix_exporter.py` — STIX 2.1 bundle emitted alongside existing ZIP export.
- `taxii_routes.py` — TAXII 2.1 server (discovery, collections, objects). Gated by `external_disclosure` capability.
- `graph_service.py` extension: new edge kinds `Indicator→Finding|Specimen|CVE|Asset|Indicator`.
- Auto-enrichment: every new `IndicatorArtifact` fans out to configured intel sources via Redis Streams; verdicts land in `payload.enrichment`.

**Acceptance:**
- MISP feed ingests; events appear in `IndicatorArtifact` with source = `misp`.
- Indicator in an active case auto-enriches with VT + OTX + MalwareBazaar verdicts within 60 s.
- STIX 2.1 bundle in report export validates with `stix2` library.
- TAXII 2.1 server advertises the configured collection; external consumer can pull with valid authorization artifact; pull without artifact denied.
- Graph slice around a single IOC surfaces all linked cases, specimens, CVEs, assets.

**Key files:**
- New: `app/ingestion/{misp,virustotal,otx,abusech,opencti,mandiant,shodan}_connector.py`, `app/services/stix_exporter.py`, `app/api/routes/taxii_routes.py`.
- Modified: `app/services/graph_service.py`.

---

## Phase D — Detection Engineering + MITRE ATT&CK (2–3 weeks)

**Goal:** Make the lab measurably good at detection engineering.

**Deliverables:**
- `attack_mapper.py` — rule-based Tetragon / Volatility → technique map; LLM fallback with self-consistency check.
- `BehaviorFinding.payload.attack_techniques` populated.
- `detection_validator.py` — ingests a proposed rule, validates against historical telemetry corpus, returns FP/FN.
- YARA live scanner on MinIO quarantine; systemd-timer re-scan on new rule publish.
- `AttackCoveragePage` — ATT&CK heatmap UI.

**Acceptance:**
- Every new `BehaviorFinding` lands with ≥1 ATT&CK technique tag (rule-based hit or LLM fallback with confidence).
- Analyst submits a Sigma rule; validator returns precision, recall, FP/FN counts against the corpus.
- YARA new-rule publish triggers a scan; hits appear in the review queue.
- `AttackCoveragePage` heatmap drills down to contributing findings.

---

## Phase E — Analyst UX (3–4 weeks)

**Goal:** Close the analyst-workstation UX gaps.

**Deliverables:**
- `RunConsolePage` rewrite: SSE event stream.
- `TimelinePage`, `CaseGraphPage`, `LineageTreePage`, `HuntPage`, `AutonomousAgentPage`, `AuthorizationCenterPage`, `DetectionCopilotPage` (pages).
- `AISidebar`, `LiveConsole`, `GroundingInspector`, `CapabilityGate` (components).
- `report_templater.py` — Jinja2 templates + pluggable emitters (PDF via WeasyPrint, Markdown, STIX, MISP event).

**Acceptance:**
- Starting a run from the UI streams live events into `RunConsolePage`.
- Case graph renders force-directed for a representative case with 50+ nodes.
- AI sidebar opens the source chunks used to ground any claim; clicking a source navigates to the underlying evidence.
- A report generated via the templater exports in all four formats; PDF renders cleanly.

---

## Phase F — Governance + Scale (2–3 weeks)

**Goal:** Harden the single-host operational story.

**Deliverables:**
- Sigstore / cosign signing of authorization artifacts, export bundles, and Merkle roots.
- Policy version history + diff UI.
- Multi-reviewer sign-off enforced in `AuthorizationCenterPage`.
- Sandbox-worker pool as a supervised systemd process consuming from Redis Streams.
- MinIO lifecycle rules for quarantine retention + report archive.
- Rekor anchor for the Merkle root (optional toggle).

**Acceptance:**
- Export bundle's cosign signature verifies externally.
- Revoking an active artifact propagates to in-flight step denial on next evaluation.
- Worker pool survives `kill -9`; restart resumes in-flight runs from Redis-stream offset.
- Rekor anchor, when enabled, carries the latest Merkle root.

---

## Phase G — Novel Capability Tracks (parallel after F)

### G1 — Autonomous Analyst Agent (3–4 weeks)

Delivers `autonomous_agent.py`, `AutonomousAgentPage`, `POST /api/v4/autonomous/runs`, SSE event stream, reviewer approval flow with signed chain-of-custody manifest.

**Acceptance:** submit a specimen; agent runs detonations + detections + report under policy; reviewer approves; `cosign verify` on the output bundle succeeds.

### G2 — Behavior-Embedding Similarity + Variant Diff (2–3 weeks)

Delivers `behavior_embedder.py`, `variant_diff.py`, `specimen_behavior_embeddings` pgvector table, similarity API, variant-diff report format.

**Acceptance:** two known variants of the same family → variant-diff report highlights behavioral + ATT&CK delta; similarity search from a third variant surfaces both within top 5 hits.

### G3 — Detection-Engineering Copilot (2 weeks)

Delivers `detection_copilot.py`, `DetectionCopilotPage`, PR-style review-to-promote flow.

**Acceptance:** AI proposes a Sigma rule; validator reports FP/FN; analyst promotes; rule appears in Sigma artifact store and is picked up on the next YARA/Sigma sweep.

### G4 — NL Hunt + Scheduled AI Threat Briefs (2 weeks)

Delivers `nl_hunt.py`, `HuntPage`, `threat_brief_scheduler.py`, systemd nightly timer.

**Acceptance:** NL query round-trips to a parsed + safety-checked structured query and renders results; nightly AI threat brief lands in the configured channel with accurate summaries of new intel + cases + ATT&CK drift.

### G5 — Bonus (2–3 weeks, opportunistic)

Delivers `counterfactual_runs.py`, `adversary_emulator.py`, `self_red_team.py`, `signed_manifest.py`.

**Acceptance:** counterfactual re-detonation produces a delta report; self-red-team harness produces a gap score; every export bundle is Sigstore-signed.

---

## Scheduling notes

- **Critical path**: A → B → D → E → F → G1. Expect 17–22 weeks on this path even with parallel tracks.
- **Parallel tracks** after A:
  - C runs with B (different code areas; shared Alembic rev lane coordinated at phase boundary).
  - D depends on B + C; can start its UI prep against C while B finishes.
  - E can start shell + SSE plumbing during B and fill in pages as D lands.
  - F is small; can interleave with G1 once policy engine is proven under load.
  - G1–G4 parallel after F.
  - G5 opportunistic throughout G1–G4.
- **Hard gate**: no Phase-G work starts until F verification passes.

---

## Phase-completion checklist (applied to every phase)

- [ ] VERIFICATION.md written with acceptance tests executed and output attached.
- [ ] Alembic migration lands with both up and down paths tested.
- [ ] Nyquist coverage gaps filled (via `/gsd:validate-phase`).
- [ ] Docs updated (architecture and capability-policy kept in lockstep).
- [ ] Merkle audit chain extended with phase-exit signed entry.
- [ ] `sheshnaag audit verify` exits 0.
