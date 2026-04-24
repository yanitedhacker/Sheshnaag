# Project Sheshnaag — V4 Architecture

**Status:** Draft (design approved; implementation pending)
**Companion docs:** `SHESHNAAG_V4_PRD.md`, `SHESHNAAG_V4_ROADMAP.md`, `SHESHNAAG_V4_CAPABILITY_POLICY.md`, `SHESHNAAG_V4_DEPLOYMENT.md`.

---

## 0. High-Level Shape

```
                    ┌────────────────────────────────────────────┐
                    │                Analyst UI (React)          │
                    │  RunConsole (SSE)  CaseGraph  AttackMap    │
                    │  AutonomousAgent  AISidebar  DetectionCopilot │
                    └─────────┬───────────────────────────┬──────┘
                              │ REST + SSE                │
                    ┌─────────▼──────────┐       ┌────────▼────────┐
                    │   FastAPI Router   │       │   TAXII 2.1     │
                    │  (tenant-scoped)   │       │   server        │
                    └─────────┬──────────┘       └────────┬────────┘
                              │                           │
                 ┌────────────┼───────────────────────────┼─────────────┐
                 │            │      Capability Policy    │             │
                 │            │   + Authorization Artifacts│            │
                 │            │   + Merkle Audit Log       │            │
                 │            ▼                            ▼             │
      ┌──────────▼──┐  ┌─────────────┐  ┌──────────────┐  ┌──────────┐ │
      │ MalwareLab  │  │ AI Agent    │  │ Threat Intel │  │ Report   │ │
      │ Service     │  │ Loop        │  │ Fabric       │  │ Templater│ │
      │ (extended)  │  │ (new)       │  │ (new)        │  │ (new)    │ │
      └──────┬──────┘  └──────┬──────┘  └──────┬───────┘  └────┬─────┘ │
             │                │                │                │      │
             ▼                ▼                ▼                ▼      │
  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────┐  │
  │ Sandbox Workers  │  │ AI Provider      │  │ Intel Connectors   │  │
  │ (Redis Streams)  │  │ Harness          │  │ (MISP/VT/OTX/…)    │  │
  │  docker_kali     │  │  Anthropic       │  │  + STIX Exporter   │  │
  │  lima (libvirt)  │  │  OpenAI          │  │                    │  │
  │  + launchers/    │  │  Gemini          │  └────────────────────┘  │
  │  + egress_enf    │  │  Azure OpenAI    │                          │
  │  + snapshot_mgr  │  │  Bedrock (SigV4) │                          │
  │  + volatility    │  │  Ollama/vLLM     │                          │
  │  + zeek/suricata │  └──────────────────┘                          │
  └──────┬───────────┘                                                 │
         │ pcap · memory · eBPF · files                                │
         ▼                                                             │
  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐    │
  │ MinIO Quarantine │  │ Postgres + pgvec │  │ Redis Streams    │    │
  │ (artifacts,      │  │ (domain, graph,  │  │ (live events,    │    │
  │  reports, SBOMs) │  │  embeddings,     │  │  work queue)     │    │
  │                  │  │  audit chain)    │  │                  │    │
  └──────────────────┘  └──────────────────┘  └──────────────────┘    │
                                                                      │
                OpenTelemetry traces + Prometheus metrics + JSON logs │
                                                                      │
                          Sigstore / Rekor (external)                 │
```

All inside a **single-host** docker-compose with systemd supervision. Everything above the dashed boundary is reachable only through the FastAPI router; every state-mutating path flows through the Capability-Policy middleware.

---

## 1. Pillar 1 — Real AI Brain

### 1.1 Provider-adapter pattern

`app/services/ai_provider_harness.py` is rewritten around a single abstract base:

```python
class NativeAIAdapter(Protocol):
    provider_key: str
    display_name: str
    capabilities: list[str]

    def health(self) -> dict: ...
    def stream(self, *, capability, prompt, grounding, tools, cache_key) -> Iterator[dict]: ...
```

Six concrete adapters:

| Adapter | File | Notes |
|---|---|---|
| `AnthropicAdapter` | `ai_adapters/anthropic.py` | `/v1/messages`, SSE, `tools` + `tool_use` blocks, `cache_control` on system + tool blocks, optional extended thinking. |
| `OpenAIAdapter` | `ai_adapters/openai.py` | `/v1/chat/completions`, SSE, `tools` (function calling), structured outputs via JSON Schema. |
| `GeminiAdapter` | `ai_adapters/gemini.py` | `streamGenerateContent`, function-calling via `tools.functionDeclarations`. |
| `AzureOpenAIAdapter` | `ai_adapters/azure_openai.py` | Azure resource URL + `api-version` query + `api-key` header; wire shape = OpenAI. |
| `BedrockAdapter` | `ai_adapters/bedrock.py` | SigV4; `InvokeModelWithResponseStream`; model-specific bodies (Anthropic-on-Bedrock, Titan, Cohere, Mistral, Llama). |
| `LocalOpenAICompatAdapter` | `ai_adapters/local.py` | Points at Ollama (`localhost:11434`) or vLLM (`localhost:8000`). Air-gapped default. |

A single `AIProviderHarness.run()` entry point resolves `provider_key` → adapter, streams the response, writes an `AISession` row per top-level invocation + a child row per tool-use step. The existing **grounding validator** (1–25 items, required) stays; the **prompt blocklist is removed** (capability policy supersedes it).

### 1.2 Tool registry

`app/services/ai_tools_registry.py` defines the callable tools exposed to models under capability-policy evaluation:

- `fetch_specimen_triage(specimen_id)` → static triage dict
- `query_knowledge(query, k=8)` → pgvector RAG hits
- `pivot_ioc(indicator_value)` → graph neighborhood of the IOC
- `run_yara_scan(ruleset_id, scope)` → matches from quarantine
- `propose_detection(kind: sigma|yara|snort|falco, draft)` → validator FP/FN
- `detonate_in_sandbox(specimen_id, profile_id)` → gated by `dynamic_detonation` capability
- `query_intel_feed(source, iocs)` → VT/OTX/MISP enrichment
- `export_external(bundle_id, target)` → gated by `external_disclosure` capability
- `run_authorized_offensive(target, recipe_id)` → gated by `offensive_research` capability + signed authorization artifact

Every tool call: evaluated against the capability policy first → executed → result appended to the `AISession.tool_trace` → streamed to the frontend.

### 1.3 pgvector RAG

`app/services/knowledge_service.py` upgrades:

- embedding dim 24 → 1024 (BGE-M3 or Voyage-3)
- storage: in-memory list → `knowledge_chunk_embeddings` table with `vector(1024)` column and IVFFLAT or HNSW index
- retrieval: BM25 → BM25 + cosine hybrid with reciprocal-rank fusion reranker
- **grounding provenance**: every AI response carries a list of `{chunk_id, sha256, rank, score}` that maps directly to clickable sources in the AI sidebar

### 1.4 Agentic loop

`app/services/ai_agent_loop.py`: a bounded ReAct-style loop.

```
for step in range(max_steps):
    response = adapter.stream(...)
    if response.stop_reason == "tool_use":
        tool_result = policy.evaluate_and_run(tool_name, args)
        context.append(tool_result)
    elif response.stop_reason == "end_turn":
        break
```

Each step is a row in `ai_agent_steps` (FK → `AISession`), with the policy decision, capability, tool input, tool output, and token counts. Used by the Autonomous Analyst Agent (Pillar 7 Track A).

---

## 2. Pillar 2 — Real Dynamic Analysis Engine

### 2.1 materialize_run_outputs rewrite

The synthetic path at `app/services/malware_lab_service.py:591` becomes a **dispatcher** over `app/lab/launchers/`:

```python
specimen_kind → launcher:
    "file/pe" | "file/msi"     → pe_launcher   (libvirt Windows VM)
    "file/elf" | "file/script" → elf_launcher  (existing docker_kali)
    "file/js" | "file/hta"     → browser_launcher (headless Chromium container)
    "email/eml" | "email/msg"  → email_launcher
    "archive/zip" | "archive/…"→ archive_launcher (extract → recurse)
    "url"                      → url_launcher  (headless browser + MITM proxy)
```

Each launcher:
1. Requests a snapshot from `snapshot_manager`.
2. Configures egress via `egress_enforcer` per profile.
3. Materializes the specimen from MinIO into the guest.
4. Executes it (real).
5. Harvests telemetry (pcap, memory, eBPF, file diff, process tree).
6. Reverts snapshot.
7. Feeds telemetry through collectors → `BehaviorFinding` rows with **confidence derived from telemetry**, not hardcoded.

### 2.2 Egress enforcer

`app/lab/egress_enforcer.py` wires:
- **nftables** rulesets per container/VM (L3/L4 allowlist enforced by the kernel).
- **dnsmasq** for DNS sinkhole mode.
- **INetSim** or **FakeNet-NG** for fake-internet mode.
- **iptables NFLOG** → pcap tap per run.

Profile config dict in `SandboxProfile.config` becomes the source-of-truth; the enforcer compiles it to active rules at run start and tears them down at run end (or on crash, idempotent reconciliation).

### 2.3 Snapshot manager

`app/lab/snapshot_manager.py` provides `with_snapshot(profile, run_id) → revert` context manager:
- `libvirt`: `virsh snapshot-create-as ... → virsh snapshot-revert`.
- `lima`: `limactl stop --force` + cow-disk rollback (`lima_provider.py:88`'s `snapshot_revert_supported: True` gets an actual implementation).
- `docker`: re-pull image + `--rm` flag plus volume tmpfs (lighter weight).

### 2.4 Volatility + Zeek

- `app/lab/volatility_runner.py`: captures memory via `virsh dump` or LiME; runs `pslist`, `malfind`, `netscan`, `cmdline`, `hollowfind`, `modscan`; normalizes hits into `BehaviorFinding` with `finding_type` prefixed `memory:`.
- `app/lab/zeek_runner.py`: runs Zeek against the captured pcap; extracts `conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`; emits an `IndicatorArtifact` per observed external connection (deduped).
- `app/lab/collectors/pcap.py`: 5-s / 20-packet cap removed; replaced by profile-config-driven limits with 0 = unlimited.

### 2.5 eBPF telemetry

`app/lab/ebpf_tracer.py` wraps Tetragon or Tracee; emits syscall events into the run's timeline stream (Redis Streams → SSE to UI). Used by `attack_mapper` in Pillar 4.

---

## 3. Pillar 3 — Threat Intel Fabric

### 3.1 New connectors

Pattern matches existing `app/ingestion/osv_connector.py`:

| Connector | Source | Auth |
|---|---|---|
| `misp_connector.py` | MISP events (pull + push) | API key |
| `virustotal_connector.py` | VT v3 file/url/domain reports | API key |
| `otx_connector.py` | AlienVault OTX pulses | API key |
| `abusech_connector.py` | URLhaus + MalwareBazaar + ThreatFox | Auth key |
| `opencti_connector.py` | OpenCTI GraphQL | API key |
| `mandiant_connector.py` | Mandiant Advantage | API key |
| `shodan_connector.py` | Shodan InternetScanner | API key |

Every connector registers under the existing `ConnectorRegistry`; scheduling via the existing `patch_scheduler`.

### 3.2 STIX 2.1 + TAXII 2.1

- `app/services/stix_exporter.py`: builds STIX bundles (Indicator, Malware, ObservedData, Report, Relationship, Sighting) from a case. Attaches to the existing ZIP export beside markdown + JSON.
- `app/api/routes/taxii_routes.py`: TAXII 2.1 server (`/taxii2/` discovery, `/api1/collections`, `/api1/collections/{id}/objects`) gated by `external_disclosure` capability + signed authorization artifact.

### 3.3 IOC pivot graph

`app/services/graph_service.py` (`ExposureGraphService`) gets new edge kinds:

- `Indicator → Finding`
- `Indicator → Specimen`
- `Indicator → CVE`
- `Indicator → Asset`
- `Indicator → Indicator` (co-occurrence within a run or case)

Stays on existing Postgres-backed `ExposureGraphNode` / `ExposureGraphEdge` model — no Neo4j dependency. A hover-over IOC in the UI opens a graph slice of all its neighbors.

### 3.4 Auto-enrichment

Every new `IndicatorArtifact` fans out to configured intel sources (fire-and-forget via Redis Streams); verdicts land in `IndicatorArtifact.payload.enrichment` with source + score + timestamp; a consensus score surfaces in the review queue.

---

## 4. Pillar 4 — Detection Engineering + MITRE ATT&CK

- `app/services/attack_mapper.py`: rule-based mapping table (Tetragon event → technique) + LLM fallback with self-consistency check.
- `BehaviorFinding.payload.attack_techniques = ["T1055.012", ...]`.
- `AttackCoveragePage` (frontend): navigator-style heatmap, filters by case / tenant / time range; cells show count + click-through to findings.
- `app/services/detection_validator.py`: ingests a proposed rule → tests against the historical telemetry corpus in Postgres partitions → returns `{true_positives, false_positives, false_negatives, precision, recall, f1}` → renders to the analyst UI.
- YARA live scanner: systemd-timer driven; scans MinIO quarantine on every new rule publish; hits land in the review queue.

---

## 5. Pillar 5 — Analyst UX

New pages (React + TypeScript, beside the existing 28):

| Page | Purpose |
|---|---|
| `AttackCoveragePage` | ATT&CK heatmap per case / tenant / timeframe |
| `CaseGraphPage` | Force-directed graph of specimens ↔ findings ↔ IOCs ↔ CVEs ↔ assets (react-flow) |
| `TimelinePage` | Chronological event timeline (uses existing `RunTimelineEvent` type) |
| `HuntPage` | Natural-language → structured query → results |
| `AutonomousAgentPage` | Submit specimen + live trace + approve-on-completion |
| `LineageTreePage` | Specimen revision tree (uses `SpecimenRevision.parent_revision_id`) |
| `AuthorizationCenterPage` | Issue, view, revoke authorization artifacts |
| `DetectionCopilotPage` | AI draft → validator FP/FN → PR-style promote |

Shared components:

| Component | Purpose |
|---|---|
| `AISidebar` | Streaming tokens + grounding provenance inspector (clickable sources) |
| `LiveConsole` | SSE event stream renderer with filters |
| `GroundingInspector` | Modal that opens the source documents used to ground a claim |
| `CapabilityGate` | Shows why an action is blocked and the authorization artifact needed |

SSE delivery:
- Backend: FastAPI `StreamingResponse` keyed by `run_id` or `ai_session_id`.
- Events are published into Redis Streams; an SSE bridge fans out per subscriber.

Reports:
- `app/services/report_templater.py`: Jinja2 templates per report type (`incident_response`, `bug_bounty`, `intel_brief`, `detection_engineering`). Emitters: PDF (WeasyPrint), Markdown, STIX, MISP event.

---

## 6. Pillar 6 — Capability Policy Era

Full details: `SHESHNAAG_V4_CAPABILITY_POLICY.md`. Brief shape:

- `app/services/capability_policy.py` — single chokepoint called at every risky action.
- Capabilities named + versioned: `dynamic_detonation`, `exploit_validation`, `red_team_emulation`, `offensive_research`, `external_disclosure`, `specimen_exfil`, `destructive_defang`.
- **Authorization artifact** — signed JSON `{capability, scope, requester, reviewer, expiry, nonce, sig (cosign)}` stored in `authorization_artifacts` table and mirrored to the Merkle audit log.
- **Merkle audit log** — append-only, Merkle-chained table; periodic root published to Rekor (optional).
- Multi-reviewer sign-off required for `offensive_research` and `external_disclosure`.

---

## 7. Pillar 7 — Novel Capability Tracks

### Track A — Autonomous Analyst Agent

`app/services/autonomous_agent.py`. Driver that wires `ai_agent_loop` + policy + tools:

```
state = ingest_specimen(spec_id)
while not terminal(state):
    step = agent_loop.next_step(state)         # model + tools
    policy.evaluate(step)                       # blocks or permits
    state = apply(step, state)                  # tool result folded in
reviewer_queue.append(state.draft_report)
```

New route: `POST /api/v4/autonomous/runs` → returns `session_id`; SSE on `GET /api/v4/autonomous/runs/{id}/events` streams the trace.

### Track B — Behavior-embedding similarity + variant diff

- `app/services/behavior_embedder.py`: feature extraction (syscall sequence, network endpoints, YARA hit set, string distribution) → concat → project to 1024-dim → pgvector.
- `specimen_behavior_embeddings` table with `vector(1024)` + IVFFLAT index.
- `app/services/variant_diff.py`: Myers-diff on feature sequences + ATT&CK delta + AI-narrated summary + auto-updated-rule proposals.

### Track C — Detection-engineering copilot

- `app/services/detection_copilot.py`: wraps agent loop with `propose_detection` tool; surfaces drafts in `DetectionCopilotPage`.
- PR-style promote flow: draft → validator report → review → `artifact_generator.py` writes the real rule.

### Track D — NL hunt + scheduled AI threat briefs

- `app/services/nl_hunt.py`: model drafts a structured query (SQL subset + graph traversal DSL); validator parses + rejects unsafe patterns; executes read-only.
- `app/services/threat_brief_scheduler.py`: systemd-timer nightly job; model synthesizes `{new_intel_today, active_cases_summary, attack_coverage_drift, reviewer_backlog}` → pushes to Slack / email / Linear via webhooks configured in `ScopePolicy.policy.channels`.

### Bonus (shipped opportunistically)

- `counterfactual_runs.py`: re-detonate with alternate egress/profile.
- `adversary_emulator.py`: reuses `recipe_schema.py` DSL.
- `self_red_team.py`: adversarial prompt harness + regression scoring.
- `signed_manifest.py`: Sigstore / cosign signing on every export bundle.

---

## 8. Data Model Additions (Alembic)

New / extended tables:

- `authorization_artifacts` (capability, scope JSON, signer, reviewer(s), expiry, sig, nonce, revoked_at).
- `audit_log_entries` (idx, previous_hash, entry_hash, actor, action, capability, payload, signed_at).
- `ai_agent_steps` (FK → ai_sessions, step_no, capability, tool_name, tool_input, tool_output, decision, tokens_in, tokens_out).
- `specimen_behavior_embeddings` (specimen_id, embedding vector(1024), feature_digest, created_at).
- `knowledge_chunk_embeddings` (chunk_id, embedding vector(1024)).
- `indicator_edges` (extends `exposure_graph_edges` with new `edge_kind` values).
- `attack_technique_tags` (finding_id, technique_id, source: rule|llm, confidence).

---

## 9. Observability

- **Traces**: OpenTelemetry SDK wired in FastAPI middleware + each service entry point. Span names: `svc.malware_lab.resolve_run_contract`, `svc.ai.stream`, `svc.sandbox.launch`, etc.
- **Metrics**: Prometheus `/metrics` retained; add: `sandbox_runs_total{status=…}`, `ai_tokens_total{provider,direction}`, `capability_evaluations_total{capability,decision}`.
- **Logs**: structured JSON via `structlog` or stdlib `JsonFormatter`; every line carries `trace_id`, `span_id`, `tenant_id`, `case_id`, `run_id` where applicable.

---

## 10. What Stays the Same

- FastAPI + SQLAlchemy + Alembic.
- React + TypeScript + vite frontend.
- Existing review queue + `AISession` row-per-AI-call pattern.
- `ScopePolicy` model + `_active_policy()` chokepoint.
- `recipe_schema.py` DSL (reused by NL hunt + adversary emulator).
- `artifact_generator.py` (extended, not replaced).
- Existing CVE intel connectors (OSV, GHSA, KEV, EPSS, NVD, Exploit-DB, patch-notes, vendor-advisory).
- JWT + tenant + scope model in `app/core/security.py` (extended with capability hooks, not rewritten).

---

## 11. What Goes Away

- `BLOCKED_PROMPT_PATTERNS` regex list in `ai_provider_harness.py` — replaced by capability policy.
- Custom-POST body shape in the old `openai-api` / `anthropic-api` adapters — replaced by native wire formats.
- Hardcoded confidence scores (0.84, 0.82, 0.88, 0.71) in `materialize_run_outputs`.
- 5-s / 20-packet pcap cap.
- In-memory 24-dim toy vectors in `knowledge_service.py`.
- SQLite as default DB — demoted to dev.
- `/tmp/sheshnaag_quarantine` — replaced by MinIO.
