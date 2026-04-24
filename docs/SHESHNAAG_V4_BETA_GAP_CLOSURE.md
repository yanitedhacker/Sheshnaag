# Sheshnaag V4 — Beta Gap Closure Spec

**Audience:** A senior engineer taking over Sheshnaag V4 and bringing it to a shippable beta without needing to page the original authors.
**Status:** Actionable hand-off. Written after Phase A + B + C landed (merge commit `2e96925` on `main`).
**Companion docs:** `SHESHNAAG_V4_PRD.md`, `SHESHNAAG_V4_ARCHITECTURE.md`, `SHESHNAAG_V4_ROADMAP.md`, `SHESHNAAG_V4_CAPABILITY_POLICY.md`, `SHESHNAAG_V4_DEPLOYMENT.md`.

---

## 0. How to read this document

Each gap is scoped so it can be handed to one engineer (or dispatched to parallel agents) without ambiguity:
- **Why it blocks beta** — the real-world reason, not abstract.
- **Files to create / modify** — absolute paths.
- **Interface / contract** — the exact shapes other code expects.
- **Acceptance tests** — how a reviewer confirms it.
- **Size** — S/M/L (1 day / 2-4 days / 5-8 days).

**Ground rule:** do not rewrite anything green. The 546 existing tests are the canary. If a change makes a test fail, treat it as a break and either fix the test purposefully or roll back.

---

## 1. Beta-ready definition

V4 is **beta-ready** when all the following hold:

| Gate | Check |
|---|---|
| **G1. Feature completeness** | Every claim in `SHESHNAAG_V4_PRD.md` §5 "Success Criteria" items 1-10 passes. Today items 1, 3, 4 pass; items 2, 5, 6, 7, 8, 9, 10 require closure work (below). |
| **G2. Analyst can drive the system without a Python REPL** | The UI exposes every backend capability a beta tester would need. Today the authorization-artifact issuance flow and several other paths are CLI-only. |
| **G3. One real end-to-end detonation has succeeded** | EICAR-class benign test specimen has been detonated on a Linux host with all infra wired; telemetry landed in Postgres with non-synthetic confidence values. |
| **G4. V3 → V4 upgrade is documented and scripted** | An existing V3 operator can run one command + follow one runbook and land on V4 without data loss. |
| **G5. Ops hardening minimum met** | MinIO quarantine, structured JSON logs, real Sigstore signing (not HMAC fallback), a supervised worker process, and a health endpoint covering all lab binaries. |
| **G6. Known V3 regression fixed** | `tests/integration/test_malware_lab_routes.py::test_run_plan_accepts_v3_metadata_and_resolves_risky_modes_to_lima` passes. Currently fails — pre-existing, but a red test ships a red signal to beta testers. |
| **G7. Autonomous Analyst Agent ships** | POST /api/v4/autonomous/runs → agent drives a case end-to-end → reviewer approves → cosign-signed manifest verifies externally. The headline novel feature. |

**Deferred to GA (explicitly NOT beta blockers):**
- Behavior-embedding similarity + variant diff (Phase G2)
- Detection copilot (Phase G3)
- NL hunt + scheduled briefs (Phase G4)
- Multi-host orchestration (V5)

**Beta tester profile:** senior security analyst on a Linux host willing to install libvirt + KVM + nftables + dnsmasq + INetSim + Volatility 3 + Zeek + Docker. ~5 to 10 trusted users. Not open enrollment.

---

## 2. Snapshot — what is already landed

### 2.1 Backend primitives (all on `main`)

| Area | Module(s) | Tests | Notes |
|---|---|---|---|
| AI harness + 6 native adapters | `app/services/ai_provider_harness.py`, `app/services/ai_adapters/` | 32 | Anthropic `/v1/messages`, OpenAI `/v1/chat/completions`, Gemini streamGenerateContent, Azure OpenAI, Bedrock (SigV4), local Ollama/vLLM |
| Tool registry | `app/services/ai_tools_registry.py` | part of agent-loop suite | 9 tools declared, each with `capability` mapping |
| Agent loop (ReAct, bounded) | `app/services/ai_agent_loop.py` | 4 | Foundation for G1 Autonomous Agent |
| Capability policy engine | `app/services/capability_policy.py`, `app/models/capability.py` | 10 | 12 capabilities; CosignSigner with HmacDevSigner fallback |
| Merkle audit log | same module + Alembic `v4a01` | inside chain tests | Append-only (Postgres trigger on PG; SQLite warn-only) |
| `sheshnaag audit verify` CLI | `scripts/sheshnaag_audit_verify.py` | smoke-tested | Exits 0 on clean chain, 1 on tamper |
| pgvector RAG | `app/services/knowledge_service.py`, `app/models/embeddings.py`, Alembic `v4a02` | 16 | HashFallback / Ollama / OpenAI embedding providers; BM25+cosine RRF |
| 7 intel connectors | `app/ingestion/{misp,virustotal,otx,abusech,opencti,mandiant,shodan}_connector.py` | 128 | All graceful on missing env |
| STIX 2.1 exporter | `app/services/stix_exporter.py` | 13 | Hand-rolled, no `stix2` dep |
| TAXII 2.1 server | `app/api/routes/taxii_routes.py` | 15 | Gated by `require_capability("external_disclosure")` |
| IOC auto-enrichment | `app/services/ioc_enrichment.py` | 13 | Parallel fan-out via ThreadPoolExecutor |
| IOC pivot graph | `app/services/graph_service.py` + Alembic `v4a03` | 4 | 5 new edge kinds; SQL-backed, no Neo4j |
| Egress enforcer | `app/lab/egress_enforcer.py` | 9 | **`dry_run=True` default** until `SHESHNAAG_EGRESS_ENFORCE=1` |
| Snapshot manager | `app/lab/snapshot_manager.py` | 7 | libvirt / lima / docker providers |
| Volatility runner | `app/lab/volatility_runner.py` | 11 | Windows + Linux plugin catalogs |
| Zeek runner | `app/lab/zeek_runner.py` | 8 | TSV log parsing + IOC extraction |
| eBPF tracer | `app/lab/ebpf_tracer.py` | 9 | Tetragon / Tracee / none backends |
| 6 specimen launchers | `app/lab/launchers/` | 22 | PE / ELF / browser / email / archive / URL |
| Real `materialize_run_outputs` | `app/services/malware_lab_service.py` | 2 integration | No more hardcoded 0.84/0.82/0.88/0.71 confidences |
| pcap cap lifted | `app/lab/collectors/pcap.py` | 8 | Default 30 s / 10 000 pkts / 10 MB; 0 = unlimited |

### 2.2 Test state (as of merge `2e96925`)

```
Full suite (without RUN_INTEGRATION_TESTS=1): 429 passed, 77 skipped, 0 failed
With RUN_INTEGRATION_TESTS=1:                  447 passed, 53 skipped, 2 failed*
```

`*` two integration failures:
- `test_malware_lab_routes.py::test_run_plan_accepts_v3_metadata_and_resolves_risky_modes_to_lima` — **pre-existing V3 bug** (setup_module doesn't commit recipe creation). See Gap 3.8.
- 23 ERRORs in `test_api_patches.py`, `test_api_risk_dashboard.py`, `test_candidate_api.py`, `test_malware_lab_routes.py` are all `Connection refused` to `http://localhost:8000` — pre-existing tests require a live API server and are unrelated to V4.

### 2.3 Alembic chain

```
20260409_0001 (V2 features)
  → v4a01 (capability policy + audit log)
  → v4a02 (pgvector embeddings)
  → v4a03 (IOC graph edges + indexes)
```

Apply + revert tested on scratch SQLite. On Postgres the pgvector extension auto-creates and IVFFLAT indexes spin up; on SQLite those steps skip with a logged warning.

### 2.4 Known merge-time fixes applied during Phase A/B/C close

Three subtle bugs got fixed during the parallel-agent merge. A senior dev needs to know about these because **the same class of bug will re-appear in Phase E/F/G work if you're not careful**.

| Bug | Root cause | Fix | Where |
|---|---|---|---|
| Capability policy `_tenant_permits` wiped uncommitted rows | `sa.inspect(session.get_bind())` opens a *sibling* DBAPI connection on in-memory SQLite + StaticPool, which resets the in-flight transaction | Use `sa.inspect(session.connection())` OR wrap the query in `session.begin_nested()` SAVEPOINT | `app/services/capability_policy.py:740` |
| Audit chain `verify_chain()` returned `signature_invalid` on clean chains | `issue()` passed the **artifact's** signature+cert into `_append_audit_entry`, so the audit row stored a signature over the artifact body instead of its own body | Remove the pass-through; let each audit row sign its own canonical body | `app/services/capability_policy.py:512` |
| Knowledge service wiped uncommitted docs during retrieval | Same sibling-connection bug as #1, in `_has_embedding_table()` | `sa.inspect(session.connection())` | `app/services/knowledge_service.py:431` |

**Rule for the engineer picking up the work:** never call `sa.inspect(engine)` or `sa.inspect(session.get_bind())` from a code path that runs inside a live session. Inspect via `session.connection()`, or catch the `OperationalError` and `session.rollback()` inside a `begin_nested()`.

---

## 3. Gap inventory

Gaps are grouped by subsystem and ordered by beta criticality (most critical first). Each gap is sized and has its own acceptance test so you can claim it independently.

### 3.1 — Analyst UI surfaces (Phase E slice) [**CRITICAL, L**]

**Why it blocks beta:** The UI still ships V3 pages only. Every new V4 capability (capability policy, TAXII, ATT&CK coverage, IOC graph, autonomous agent, streaming telemetry) is invisible from the browser. A beta tester cannot issue an authorization artifact without a Python REPL. A beta tester cannot observe a live detonation. A beta tester cannot see the IOC pivot graph C3 built.

**Minimum-for-beta pages (build these):**

#### 3.1.1 `AuthorizationCenterPage` [**CRITICAL, M**]
- Path: `frontend/src/pages/AuthorizationCenterPage.tsx`
- Shows table of `AuthorizationArtifact` rows filtered by capability / state / expiry.
- "Request Authorization" form with capability-aware scope fields.
- Reviewer inbox with sign-approve / sign-reject actions (signs via backend — analyst's browser doesn't hold the signing key).
- Revoke button.
- "Chain verification" panel calling `GET /api/v4/authorization/chain/root` and `GET /api/v4/authorization/chain/verify`.
- **Dependency:** backend routes under `app/api/routes/authorization_routes.py` don't exist yet (the capability policy service is there but no HTTP surface). Must be added:
  - `POST /api/v4/authorization/request`
  - `POST /api/v4/authorization/{artifact_id}/approve`
  - `POST /api/v4/authorization/{artifact_id}/revoke`
  - `GET /api/v4/authorization`
  - `GET /api/v4/authorization/chain/root`
  - `GET /api/v4/authorization/chain/verify`
  - Register in `app/api/routes/__init__.py`.
- **Acceptance:** without this page the only way to mint an `external_disclosure` artifact is curl. The TAXII endpoints Phase C shipped are unusable without it. Analyst can request → Reviewer can approve → Analyst can revoke → chain verifies → verification panel shows green root.

#### 3.1.2 `RunConsolePage` rewrite (live SSE) [**CRITICAL, M**]
- Path: `frontend/src/pages/RunConsolePage.tsx` (exists; replace)
- Today it reads a static run's evidence list.
- Must stream events via SSE from `GET /api/v4/runs/{run_id}/events` (backend route to be added).
- Event types (already produced by `ebpf_tracer.py`, `zeek_runner.py`, `volatility_runner.py`, and the launcher): `process_exec`, `network_conn`, `dns_query`, `syscall`, `yara_hit`, `memory_finding`, `egress_blocked`, `snapshot_reverted`, `run_completed`.
- UI: scrollable event stream with filters + severity coloring + timestamp deltas.
- **Backend dependency:** `app/api/routes/live_run_routes.py` (new) that subscribes to the Redis Stream key `sheshnaag:run:{run_id}:events` (see Gap 3.3.2 for Redis wiring). Until Redis is wired, a temporary in-memory pub/sub channel per process is acceptable for beta.
- **Acceptance:** start a detonation → console shows >20 events live → closing the browser disconnects cleanly.

#### 3.1.3 `AttackCoveragePage` [**CRITICAL, M**]
- Path: `frontend/src/pages/AttackCoveragePage.tsx` (new)
- MITRE ATT&CK Navigator-style heatmap.
- Reads from `GET /api/v4/attack/coverage?tenant_slug=...&since=...` — returns `{tactics: {[tactic]: {techniques: {[id]: {count, confidence_avg, finding_ids: []}}}}}`.
- Backend: `app/services/attack_mapper.py` (new, see Gap 3.2.1) produces `BehaviorFinding.payload.attack_techniques: ["T1055.012", ...]`; this page reads those.
- Interactivity: click a cell → modal listing contributing findings with links to the cases.
- **Acceptance:** after three runs against different specimens, the heatmap shows distinct techniques colored by count; clicking opens a modal with the correct findings.

#### 3.1.4 `CaseGraphPage` [**IMPORTANT, M**]
- Path: `frontend/src/pages/CaseGraphPage.tsx` (new)
- Force-directed graph (library: `react-flow` or `vis-network`) of specimens ↔ findings ↔ IOCs ↔ CVEs ↔ assets.
- Backend: `GET /api/v4/cases/{case_id}/graph` — `ExposureGraphService.ioc_neighborhood(...)` already exists; wrap it.
- **Acceptance:** open a case with 3 specimens + 8 IOCs + 2 linked CVEs → graph renders ≥12 nodes with labeled edges, dragging works, hovering a node shows metadata.

#### 3.1.5 `AISidebar` + `GroundingInspector` components [**IMPORTANT, S**]
- Paths: `frontend/src/components/AISidebar.tsx`, `frontend/src/components/GroundingInspector.tsx`
- AISidebar wraps a streaming chat against `POST /api/v3/ai/sessions/stream` (NEW SSE variant — current route is synchronous).
- GroundingInspector renders the `grounding` array from any `AISession` response as clickable chips; clicking opens the source document.
- Reusable across: review screens, case details, autonomous agent page, hunt page (later).
- **Backend dependency:** convert `app/api/routes/ai_routes.py::create_ai_session` to also support SSE via `?stream=true`. The harness already streams; just plumb it.
- **Acceptance:** place AISidebar on CaseDetail → open → tokens stream in → click a grounding chip → modal shows the source KnowledgeChunk with its sha256.

#### 3.1.6 `CapabilityGate` component [**IMPORTANT, S**]
- Path: `frontend/src/components/CapabilityGate.tsx`
- Wraps a button: `<CapabilityGate capability="external_disclosure" scope={{tenant_id}}> <Button>Export</Button> </CapabilityGate>`
- Renders the inner button if the backend response to `GET /api/v4/capability/check?capability=...&scope=...` says `permitted: true`; otherwise renders a disabled button with a tooltip "Needs `external_disclosure` authorization" + a "Request" link that opens AuthorizationCenterPage pre-filled.
- **Backend dependency:** `GET /api/v4/capability/check` (new, thin wrapper over `CapabilityPolicy.evaluate()`).
- **Acceptance:** wrap TAXII export button on the Report page; for a tenant without the artifact, button is disabled with tooltip; after issuing the artifact + approving, button enables.

**Deferred to post-beta:**
- `AutonomousAgentPage` — covered in Gap 3.4
- `TimelinePage`, `HuntPage`, `DetectionCopilotPage`, `LineageTreePage` — defer.

#### 3.1.7 Navigation + routing
- Modify `frontend/src/components/Layout.tsx` to add nav entries for the four new pages.
- Modify `frontend/src/App.tsx` (or whatever does routing) to register routes.
- Modify `frontend/src/api.ts` + `frontend/src/types.ts` to add typed API methods + types for the new endpoints (authorization, attack coverage, capability check, live-run SSE).

**Estimate:** ~7-9 days of frontend + related backend-route work. Parallelizable into UI person + backend person.

---

### 3.2 — ATT&CK mapping + detection engineering (Phase D slice) [**CRITICAL, M**]

**Why it blocks beta:** AttackCoveragePage (Gap 3.1.3) has nothing to render until `BehaviorFinding.payload.attack_techniques` is populated. Today nothing writes that field.

#### 3.2.1 `app/services/attack_mapper.py` (new) [**CRITICAL, M**]

**Contract:**
```python
class AttackMapper:
    def __init__(self, session: Session, *, llm_fallback: bool = True): ...
    def map_finding(self, finding: BehaviorFinding) -> list[dict]:
        """Returns [{"technique_id": "T1055.012", "confidence": 0.83, "source": "rule|llm", "rationale": "..."}]"""
    def map_run(self, run: LabRun) -> None:
        """Walks all findings for the run, attaches techniques into finding.payload['attack_techniques']."""
```

**Implementation:**
- Rule table: dict mapping (collector kind, signal) → technique id. Seed from MITRE's official `enterprise-attack.json` bundled under `app/data/attack/` (add a fetch script).
  - `ebpf:execve(cmd=powershell.exe -Enc ...)` → `T1059.001`
  - `ebpf:ptrace(ATTACH)` → `T1055.008`
  - `volatility:malfind(hit)` → `T1055.012`
  - `zeek:conn(dest on C2 indicator list)` → `T1071.001`
  - `yara:CobaltStrike_Shellcode` → `T1055`
  - `fs:write(LocalState\...\runtime_broker.exe)` → `T1547.001`
  - etc.
- LLM fallback: when no rule matches and `llm_fallback=True`, call the AI harness with a restricted prompt containing the finding payload + ask for the 1-3 most likely ATT&CK techniques with rationales. Low temperature, structured output. Store `source="llm"` and `confidence<=0.6`.
- Self-consistency check: run the LLM twice; if disagreement, discard.
- Persist to `BehaviorFinding.payload["attack_techniques"]` as a list of dicts.

**Wire-in:** call `AttackMapper(session).map_run(run)` at the end of `materialize_run_outputs` in `app/services/malware_lab_service.py`.

**Acceptance tests:**
- Unit tests for rule-based hits (4+ rules).
- Unit test for LLM fallback path (mock harness).
- Integration test: seed a run with three canned telemetry findings → call `map_run` → each gets ≥1 technique tag.

**Size:** 3-4 days.

#### 3.2.2 `app/api/routes/attack_routes.py` (new) [**IMPORTANT, S**]

- `GET /api/v4/attack/coverage?tenant_slug=...&since=...` → AttackCoveragePage data.
- `GET /api/v4/attack/technique/{id}?tenant_slug=...` → all findings tagged with that technique.
- Register in `app/api/routes/__init__.py`.
- **Size:** 1 day.

#### 3.2.3 `app/services/detection_validator.py` (defer to post-beta)

Runs a proposed Sigma/YARA/Snort rule against the historical telemetry corpus and reports precision/recall. Nice-to-have for beta; **ship after beta** unless the detection copilot UI becomes a beta ask.

#### 3.2.4 YARA live scanner (defer to post-beta)

Rescan MinIO quarantine on new YARA rule publish. Useful but not blocking.

---

### 3.3 — Ops hardening (Phase F slice) [**CRITICAL, M**]

#### 3.3.1 MinIO quarantine wiring [**CRITICAL, M**]

**Why it blocks beta:** Quarantine currently writes to `/tmp/sheshnaag_quarantine` (see `app/services/malware_lab_service.py::__init__` around line 130). This is ephemeral on any managed Linux host and a data-loss risk on any reboot.

**Plan:**
- Add `minio` service to `docker-compose.yml`.
- Env vars: `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`, `MINIO_ENDPOINT`, `MINIO_QUARANTINE_BUCKET=sheshnaag-quarantine`, `MINIO_REPORTS_BUCKET=sheshnaag-reports`.
- New module `app/core/object_store.py` with:
  ```python
  class ObjectStore:
      def put(self, bucket: str, key: str, data: bytes | BinaryIO, *, sha256: str | None = None) -> str: ...
      def get(self, bucket: str, key: str) -> bytes: ...
      def presigned_url(self, bucket: str, key: str, *, ttl_seconds: int = 600) -> str: ...
      def delete(self, bucket: str, key: str) -> None: ...
  ```
- Implementation: `minio` Python client (new dependency).
- Bootstrap script `scripts/v4/minio_provision.py` creates buckets + lifecycle rules (retention default 90 days).
- Replace every `/tmp/sheshnaag_quarantine` / `/tmp/sheshnaag_reports` path in `malware_lab_service.py` and launchers with ObjectStore calls.
- **Migration:** a one-time script `scripts/v4/migrate_quarantine_to_minio.py` walks the existing `/tmp/sheshnaag_quarantine` tree, uploads each file to MinIO, verifies sha256, updates `SpecimenRevision.content_ref` to the new MinIO URI format.

**Acceptance:**
- Submit a specimen → file lands in MinIO with expected sha256 + metadata → can download via presigned URL.
- Restart docker-compose → specimen still retrievable.
- Migration script moves existing `/tmp` quarantine files to MinIO + updates DB rows with 0 mismatches.

**Size:** 2-3 days.

#### 3.3.2 Redis Streams for live events [**CRITICAL, S**]

**Why it blocks beta:** RunConsolePage live-SSE (Gap 3.1.2) needs a broker.

**Plan:**
- Redis is already in `docker-compose.yml`. Just wire it.
- New module `app/core/event_bus.py`:
  ```python
  class EventBus:
      def publish(self, stream: str, event: dict) -> str:  # returns stream entry id
      def subscribe(self, stream: str, *, last_id: str = "$") -> Iterator[dict]:  # blocking
  ```
- Streams:
  - `sheshnaag:run:{run_id}:events` — fanout from launchers + telemetry runners
  - `sheshnaag:ioc_enrichment:work` — enqueue from C2's `IocEnrichment`
  - `sheshnaag:audit:events` — optional mirror of the Merkle log for live-audit tailing
- Hook into `malware_lab_service.py::materialize_run_outputs` so each telemetry event publishes.
- SSE route `GET /api/v4/runs/{run_id}/events` pulls from `sheshnaag:run:{run_id}:events` and forwards.

**Acceptance:** start a run from the API → `redis-cli XREAD` on the stream yields events in real time → AttackCoveragePage receives them via SSE without 2 s latency.

**Size:** 1-2 days.

#### 3.3.3 Real Sigstore signing [**IMPORTANT, S**]

**Why it matters for beta:** Today `capability_policy.py` auto-falls-back to `HmacDevSigner` when `sigstore` pip isn't installed. Beta testers will run this and think they're getting transparency-log-backed signatures — they aren't. Prints one WARNING at startup, but easy to miss.

**Plan:**
- Add `sigstore>=3.0` to `requirements.txt` (no longer optional).
- Wire `CosignSigner` to actually use `sigstore-python` keyless flow (OIDC) OR key-based flow with mounted Fulcio cert + Rekor upload.
- Make `SHESHNAAG_AUDIT_SIGNER=cosign` the default in `docker-compose.yml` env for the API service.
- Add `REKOR_URL` env var; when set, publish entry hashes to Rekor.
- If `SHESHNAAG_AUDIT_SIGNER=hmac` is explicitly requested, preserve the HmacDevSigner path for local dev.

**Acceptance:** issue an artifact → `sheshnaag audit verify` succeeds and also prints the Rekor entry URL → Rekor UI shows the entry.

**Size:** 2 days.

#### 3.3.4 Structured JSON logging [**IMPORTANT, S**]

**Why it matters for beta:** Debugging a beta-tester's failure report requires real log correlation; the current stdlib logger output is unstructured strings.

**Plan:**
- Add `structlog` (or use stdlib `logging.Formatter` with JSON output — don't add a dep unless structlog's features are needed).
- Replace `logger.info("created ...")` calls with `logger.info("…", run_id=..., tenant_id=..., capability=...)`.
- Every log carries `trace_id` (from OpenTelemetry — see 3.3.5), `span_id`, `tenant_id`, `run_id`, `case_id` where applicable.
- Ship a `docs/LOG_SCHEMA.md` describing the stable field names.

**Acceptance:** `docker compose logs api | jq 'select(.level=="ERROR")'` filters cleanly.

**Size:** 1-2 days.

#### 3.3.5 OpenTelemetry instrumentation [**IMPORTANT, S**]

**Plan:**
- Add `opentelemetry-distro`, `opentelemetry-instrumentation-fastapi`, `opentelemetry-instrumentation-sqlalchemy`, `opentelemetry-exporter-otlp`.
- Add `otel-collector` service to `docker-compose.yml`.
- Wire `FastAPIInstrumentor.instrument_app(app)` + `SQLAlchemyInstrumentor().instrument(engine=...)` in `app/main.py`.
- Span naming: `svc.malware_lab.resolve_run_contract`, `svc.ai.stream`, `svc.sandbox.launch`, etc.

**Acceptance:** `otel-collector` logs span records; `curl /api/v3/cases/1` produces a span tree.

**Size:** 1 day.

#### 3.3.6 Sandbox-worker process pool [**CRITICAL, M**]

**Why it blocks beta:** Right now launchers run synchronously inside the API request. A detonation taking 60 s blocks an entire worker. A beta tester will hit this on their second try.

**Plan:**
- New module `app/workers/sandbox_worker.py`. Consumes from Redis Stream `sheshnaag:sandbox:work`. Each message:
  ```json
  {"run_id": 123, "specimen_id": 173, "profile_id": 5, "actor": "alice@x", "correlation_id": "..."}
  ```
- Worker reuses `SheshnaagService.materialize_run_outputs(...)`.
- Supervised by `supervisord` inside the container (so N instances survive `kill -9`).
- `docker-compose.yml` gets a new `worker` service (build: same Dockerfile, command: `python -m app.workers.sandbox_worker`).
- API route `POST /api/v3/runs/{run_id}/execute` changes: instead of calling `materialize_run_outputs` inline, it enqueues to Redis Stream and returns immediately with the run in state `queued`. Status polling continues to work.

**Acceptance:** submit 5 runs in parallel → all 5 start processing within 1 s → no API request blocks for more than 500 ms.

**Size:** 2-3 days.

#### 3.3.7 Lab dependencies health endpoint [**IMPORTANT, S**]

**Why it matters for beta:** Beta testers will email you "it doesn't work" when a binary is missing. Auto-detect and surface.

**Plan:**
- `GET /api/v4/ops/health` returns:
  ```json
  {
    "api": "ok",
    "db": "ok",
    "redis": "ok",
    "minio": "ok",
    "lab_deps": {
      "nft": "ok",
      "dnsmasq": "ok",
      "inetsim": "missing",
      "virsh": "ok",
      "limactl": "ok",
      "vol": "ok",
      "zeek": "missing",
      "tetragon": "missing"
    },
    "ai_providers": {"anthropic": "configured", "openai": "unconfigured", ...}
  }
  ```
- Reuses `EgressEnforcer._binary_ok` / `VolatilityRunner.health()` etc.

**Acceptance:** curl the endpoint on a machine missing Zeek → response shows `"zeek": "missing"`; install Zeek → response flips to "ok".

**Size:** 0.5 day.

---

### 3.4 — Autonomous Analyst Agent (Phase G1) [**CRITICAL, L**]

**Why it blocks beta:** Every conversation with potential beta testers has led with "you mean the thing where an AI does the whole case on its own?" Cutting this from beta turns V4 into "V3 + better plumbing" and breaks the narrative committed in the PRD.

#### 3.4.1 `app/services/autonomous_agent.py` [**CRITICAL, L**]

**Contract:**
```python
class AutonomousAgent:
    def __init__(self, session: Session, *, provider_key: str = "anthropic"): ...
    def run(self, *, tenant: Tenant, specimen_id: int, actor: str) -> AutonomousRunResult:
        """
        Drive a full case end-to-end:
          1. Capability check ``autonomous_agent_run``.
          2. Create AnalysisCase.
          3. Pick sandbox profile via policy.
          4. Plan + execute LabRun (enqueues to worker pool; streams events).
          5. After run completes: ATT&CK-map findings, enrich IOCs, draft Sigma + YARA,
             propose prevention artifacts.
          6. Generate MalwareReport (draft state).
          7. Queue for human review; return session id.

        Every step is a signed AISession row. Tool uses are captured in
        `ai_agent_steps`. The whole session references the authorization
        artifact that unlocked ``autonomous_agent_run``.
        """
```

**Implementation leverages Phase A infra:**
- Uses `app/services/ai_agent_loop.py::AIAgentLoop`.
- Tools are the 9 already declared in `app/services/ai_tools_registry.py` — most of them just need real implementations (currently stubbed). For beta, minimum real implementations needed:
  - `fetch_specimen_triage` — read `Specimen` + latest `SpecimenRevision.static_triage`.
  - `query_knowledge` — call `KnowledgeRetrievalService.search()`.
  - `pivot_ioc` — call `ExposureGraphService.ioc_neighborhood()`.
  - `run_yara_scan` — call a thin YARA scanner against the specimen file (library: `yara-python`).
  - `propose_detection` — feed an AI-drafted rule into `detection_validator.py` (if shipped) or just persist as a draft prevention artifact.
  - `detonate_in_sandbox` — enqueue to Redis Stream + return once run completes (poll with 5 s backoff up to 10 min).
  - `query_intel_feed` — call `IocEnrichment.enrich()`.
  - `export_external` — gated capability; not used by the default autonomous flow (only when user asks).
  - `run_authorized_offensive` — same; gated, not used by default.

**Safety guarantees:**
- Max 15 agent steps per run (bounded via `AIAgentLoop`).
- Every tool call logged to `ai_agent_steps`.
- Capability policy evaluates at each tool call.
- Reviewer approval required before the drafted MalwareReport moves out of `draft` state.

#### 3.4.2 `app/api/routes/autonomous_routes.py` [**CRITICAL, S**]

- `POST /api/v4/autonomous/runs` body `{specimen_id, provider_key?}` → returns `{session_id}`.
- `GET /api/v4/autonomous/runs/{session_id}` → poll state.
- `GET /api/v4/autonomous/runs/{session_id}/events` → SSE stream of agent steps.
- `POST /api/v4/autonomous/runs/{session_id}/approve` → reviewer approval.
- `POST /api/v4/autonomous/runs/{session_id}/reject` → reviewer rejection with reason.
- All gated by `require_capability("autonomous_agent_run")` except the GET endpoints.

#### 3.4.3 `AutonomousAgentPage` [**CRITICAL, M**]

- Path: `frontend/src/pages/AutonomousAgentPage.tsx`
- Left: "Submit specimen" form.
- Center: live SSE trace of agent steps — each step is a card showing tool name, input summary, output summary, duration, capability decision.
- Right: AISidebar showing the model's narration.
- Bottom: when the agent finishes, shows the drafted report with "Approve" / "Reject with notes" buttons.
- **Acceptance (end-to-end):** submit a benign EICAR-class specimen → agent runs detonation + enrichment + drafts report under a valid `autonomous_agent_run` artifact → reviewer approves → signed chain-of-custody manifest verifies via `cosign verify`.

**Size:** 7-10 days (agent logic 3-4, API 1, frontend 3-5).

---

### 3.5 — V3 → V4 migration path [**CRITICAL, S**]

**Why it blocks beta:** Existing V3 operators can't upgrade. Every beta tester onboarding becomes a "fresh install" conversation.

**Plan:**
- Write `docs/SHESHNAAG_V3_TO_V4_UPGRADE.md` — step-by-step runbook.
- Write `scripts/v4/upgrade_from_v3.sh` that:
  1. `pg_dump` the V3 DB (and SQLite if applicable).
  2. `alembic upgrade head` — applies `v4a01`, `v4a02`, `v4a03`.
  3. Seeds default V4 scope policy extension (includes V4 AI provider keys alongside V3 aliases — already done in `DEFAULT_POLICY`, but existing tenants' stored policies need updating via a one-off data migration).
  4. Invokes `scripts/v4/migrate_quarantine_to_minio.py` to move `/tmp/sheshnaag_quarantine` into MinIO.
  5. Validates: every pre-migration specimen has a matching MinIO object with correct sha256.
- Rollback plan: since Alembic downgrades are tested, `alembic downgrade 20260409_0001` + restore `pg_dump` backup works.

**Acceptance:** a V3 deployment with 10 specimens + 3 cases + 1 report can be upgraded in < 10 minutes with zero data loss; the analyst UI shows everything present post-migration.

**Size:** 1-2 days.

---

### 3.6 — Production-grade sandbox execution [**CRITICAL, M**]

**Why it blocks beta:** `EgressEnforcer` defaults to `dry_run=True` (see `app/lab/egress_enforcer.py`). Every launcher falls back to dry-run on missing binaries. On a typical Linux host without libvirt+nftables+INetSim+dnsmasq+Volatility+Zeek configured, a "detonation" produces scaffolded telemetry dicts, not real execution. Beta testers expect real behavior.

**Plan:**

#### 3.6.1 `scripts/v4/install_host_deps.sh` [**CRITICAL, S**]
- Detects distro (Ubuntu 22/24, Debian 12, Fedora 40).
- Installs: `nftables`, `dnsmasq`, `inetsim`, `libvirt-daemon-system`, `qemu-kvm`, `volatility3`, `zeek`, `wireshark-common` (for `tshark` used by pcap collector), `yara`.
- Optional: `lima` (for mac dev — but beta is Linux-only), `tetragon` via Helm chart note.
- Creates `sheshnaag` system user with libvirt + docker group membership.
- Creates systemd unit `sheshnaag-egress-enforcer.service` that loads the baseline nft ruleset + keeps dnsmasq running.
- Final `POST /api/v4/ops/health` check — bails if any required binary missing.

**Acceptance:** on a fresh Ubuntu 24 VM, running this script + `docker compose up` produces a fully working V4 stack that a detonation smoke test passes against.

**Size:** 1-2 days.

#### 3.6.2 Default `SHESHNAAG_EGRESS_ENFORCE=1` in `docker-compose.yml` [**CRITICAL, XS**]
- Currently every EgressEnforcer instance is dry-run by default.
- For beta production, flip to enforce.
- Keep dev override available.

#### 3.6.3 End-to-end detonation smoke test [**CRITICAL, S**]
- `tests/e2e/test_real_detonation.sh` — shell harness.
  - Seeds an EICAR-class benign test specimen.
  - `POST /api/v3/runs` to queue.
  - Waits for run to complete.
  - Asserts: pcap > 5 s captured, memory dump present, ≥1 Volatility finding, ≥1 Zeek indicator, no synthetic confidence values in the row set.
- CI can skip this (requires real host); documented as a pre-beta manual check.

**Size:** 1 day.

---

### 3.7 — Pre-existing V3 test regression [**IMPORTANT, S**]

**Symptom:** `tests/integration/test_malware_lab_routes.py::test_run_plan_accepts_v3_metadata_and_resolves_risky_modes_to_lima` returns 400 "Recipe not found."

**Root cause:** `setup_module()` at line 72 creates a recipe via `SheshnaagService.create_recipe` + `approve_recipe_revision` but never calls `session.commit()` before `session.close()`. The first test (`test_v3_route_flow_...`) passes because it uses HTTP which commits per-request; the second test references `globals()["DOCKER_RECIPE_ID"] = docker_recipe["id"]` but the recipe isn't actually in the DB because setup_module rolled back.

**Confirmed pre-existing:** reproduced on clean `git checkout a3c4b25` (before V4) — failure is identical.

**Fix:** add `session.commit()` before `session.close()` in `setup_module`. One-line change.

**Acceptance:** `RUN_INTEGRATION_TESTS=1 pytest tests/integration/test_malware_lab_routes.py` → both tests pass.

**Size:** 15 minutes.

---

### 3.8 — Documentation + runbooks [**IMPORTANT, S**]

**Why it blocks beta:** beta testers need operating docs.

**Add to `docs/`:**
- `SHESHNAAG_V3_TO_V4_UPGRADE.md` — covered in 3.5.
- `SHESHNAAG_V4_BETA_OPERATOR_RUNBOOK.md` — daily ops: what to watch, how to rotate signing keys, how to revoke a compromised authorization artifact, how to debug a stuck run.
- `SHESHNAAG_V4_TROUBLESHOOTING.md` — known failure modes (`vol` binary missing, dnsmasq port conflict, Postgres migration failed, etc.) with resolutions.
- Update `README.md` to point beta operators at the V4 runbook.

**Size:** 1-2 days.

---

## 4. Contracts cheat-sheet (for implementers)

### 4.1 Adding a new API route

```python
# app/api/routes/my_feature_routes.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_sync_session
from app.core.security import require_writable_tenant, require_capability

router = APIRouter(prefix="/api/v4/my-feature", tags=["my-feature"])

@router.get("")
def list_things(
    tenant_slug: str,
    session: Session = Depends(get_sync_session),
    _gate: None = Depends(require_capability("some_capability")),  # optional
):
    tenant = require_writable_tenant(session, tenant_slug=tenant_slug)
    return MyService(session).list(tenant)
```

Then register in `app/api/routes/__init__.py` matching the existing pattern.

### 4.2 Adding a new launcher

Implement `Launcher` Protocol from `app/lab/launchers/base.py`; register in `app/lab/launchers/__init__.py`; `dispatch_launcher(specimen_kind, metadata)` will pick it up.

### 4.3 Adding a new intel connector

Copy `app/ingestion/osv_connector.py` or `misp_connector.py` as a template. Register in `app/ingestion/__init__.py`. Tests follow `tests/unit/test_misp_connector.py` pattern — mock HTTP only.

### 4.4 Adding an AI tool

`app/services/ai_tools_registry.py`:
```python
TOOL_REGISTRY["my_tool"] = Tool(
    name="my_tool",
    description="Short description the model sees.",
    input_schema={"type": "object", "properties": {...}, "required": [...]},
    capability="my_capability_if_risky_else_None",
    callable=_my_tool_impl,
)
```

`AIAgentLoop` picks it up automatically. Capability policy evaluates at each invocation.

### 4.5 Adding an Alembic migration

```
revision      = "v4a04"            # sequential
down_revision = "v4a03"            # chain linearly
```

- Postgres-specific DDL guarded by `if op.get_context().dialect.name == 'postgresql': ...`
- SQLite fallback: either skip with warning, or use `batch_alter_table()` — but be aware of the CircularDependencyError in batch ops seen in `20260409_0001` (that migration has a latent bug that's unrelated but will bite if you modify it).

### 4.6 The SQLite+StaticPool gotcha (re-read §2.4)

**Never:**
```python
sa.inspect(engine).get_table_names()
sa.inspect(session.get_bind()).has_table("…")
```

**Always:**
```python
sa.inspect(session.connection()).has_table("…")
# OR
try:
    with session.begin_nested():
        session.execute(select(...))
except Exception:
    return False  # don't rollback the outer transaction
```

---

## 5. Risk inventory

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Real detonation on beta host reveals ~10 bugs no one's seen | High | Medium | Run `tests/e2e/test_real_detonation.sh` pre-beta on a representative Linux host. |
| Sigstore wiring delays beta | Medium | Low | If CosignSigner is hard to land cleanly, ship beta with HMAC + a loud warning banner. |
| Autonomous agent loops pathologically | Medium | Medium | `AIAgentLoop` is bounded at 15 steps. Add a hard wall-clock timeout (10 min per agent run). Monitor token spend per session. |
| Postgres+pgvector migration breaks on a tester's older PG | Low | High | Document minimum PG 15 in the runbook; fail fast at bootstrap if lower. |
| Capability-policy artifact signing key is lost | Medium | Critical | Key rotation runbook; keys backed up encrypted; existing artifacts get a grace period via a new audit entry. |
| Beta tester sends a real malware specimen somewhere cloud | Medium | Legal | Default policy denies `cloud_ai_provider_use` on any `Specimen` whose `risk_level` ≥ `high`. Document this loudly. |
| TAXII export to partner leaks tenant-confidential context | Medium | High | `external_disclosure` requires dual-reviewer + engagement-doc digest; add a pre-export diff UI showing exactly which SDOs will ship (not in this spec — candidate post-beta). |

---

## 6. File-level checklist

### Backend new files

- [ ] `app/api/routes/authorization_routes.py`
- [ ] `app/api/routes/attack_routes.py`
- [ ] `app/api/routes/live_run_routes.py`
- [ ] `app/api/routes/autonomous_routes.py`
- [ ] `app/core/object_store.py`
- [ ] `app/core/event_bus.py`
- [ ] `app/services/attack_mapper.py`
- [ ] `app/services/autonomous_agent.py`
- [ ] `app/workers/__init__.py`
- [ ] `app/workers/sandbox_worker.py`
- [ ] `app/data/attack/enterprise-attack.json` (fetched via a build script)

### Backend modifications

- [ ] `app/api/routes/__init__.py` — register 4 new routers
- [ ] `app/services/ai_provider_harness.py` — add `/api/v3/ai/sessions/stream` SSE variant (or new route under v4)
- [ ] `app/services/ai_tools_registry.py` — replace stub tool implementations with real ones
- [ ] `app/services/malware_lab_service.py` — swap `/tmp/...` paths for ObjectStore calls; call `AttackMapper` at end of `materialize_run_outputs`; enqueue to Redis Stream instead of inline execute
- [ ] `app/services/capability_policy.py` — make Sigstore path the default; wire Rekor anchor
- [ ] `app/core/security.py` — add `require_capability_or_raise_http` variant that works inside non-request contexts
- [ ] `app/main.py` — OpenTelemetry init; structured log init
- [ ] `app/core/config.py` — add new env vars (MINIO_*, REKOR_*, OTEL_*, SHESHNAAG_EGRESS_ENFORCE default)
- [ ] `docker-compose.yml` — add `minio`, `worker`, `otel-collector` services; mount libvirt socket into `worker`; add `SHESHNAAG_EGRESS_ENFORCE=1` env for `api` + `worker`
- [ ] `Dockerfile` — bake in the lab binaries that are safe to ship (vol, zeek, yara-python) if you want a one-container target; otherwise require `install_host_deps.sh` on the host
- [ ] `tests/integration/test_malware_lab_routes.py` — add missing `session.commit()` in `setup_module` (Gap 3.7)
- [ ] `requirements.txt` — add `minio`, `sigstore`, `opentelemetry-*`, `structlog`, `yara-python`

### Frontend new files

- [ ] `frontend/src/pages/AuthorizationCenterPage.tsx`
- [ ] `frontend/src/pages/AttackCoveragePage.tsx`
- [ ] `frontend/src/pages/CaseGraphPage.tsx`
- [ ] `frontend/src/pages/AutonomousAgentPage.tsx`
- [ ] `frontend/src/components/AISidebar.tsx`
- [ ] `frontend/src/components/GroundingInspector.tsx`
- [ ] `frontend/src/components/LiveConsole.tsx`
- [ ] `frontend/src/components/CapabilityGate.tsx`

### Frontend modifications

- [ ] `frontend/src/pages/RunConsolePage.tsx` — full rewrite (SSE)
- [ ] `frontend/src/components/Layout.tsx` — new nav entries
- [ ] `frontend/src/App.tsx` — register routes
- [ ] `frontend/src/api.ts` + `types.ts` — typed methods/types for new endpoints; add SSE helper

### Scripts / ops

- [ ] `scripts/v4/install_host_deps.sh`
- [ ] `scripts/v4/minio_provision.py`
- [ ] `scripts/v4/migrate_quarantine_to_minio.py`
- [ ] `scripts/v4/upgrade_from_v3.sh`
- [ ] `scripts/v4/generate_audit_signing_key.sh` (exists as a shim; make real)
- [ ] `tests/e2e/test_real_detonation.sh`

### Docs

- [ ] `docs/SHESHNAAG_V3_TO_V4_UPGRADE.md`
- [ ] `docs/SHESHNAAG_V4_BETA_OPERATOR_RUNBOOK.md`
- [ ] `docs/SHESHNAAG_V4_TROUBLESHOOTING.md`
- [ ] `docs/LOG_SCHEMA.md`
- [ ] Update `README.md`

---

## 7. Test strategy

### 7.1 Unit (target: ≥ 90% of touched code)

- Subprocess boundaries: mock with `unittest.mock.patch("subprocess.run", ...)` OR fake a binary's output via a stub script on `$PATH`.
- HTTP boundaries: `respx` or `httpx.MockTransport`.
- Existing pattern examples: `tests/unit/test_misp_connector.py`, `tests/unit/test_volatility_runner.py`.

### 7.2 Integration (RUN_INTEGRATION_TESTS=1)

- FastAPI TestClient against in-memory SQLite + StaticPool.
- Seed via `setup_module()` that commits after every write (don't repeat the Gap 3.7 mistake).
- Two reference patterns: `tests/integration/test_taxii_routes.py` (capability-gated), `tests/integration/test_materialize_run_outputs_v4.py` (full pipeline).

### 7.3 End-to-end (manual, pre-beta)

- `tests/e2e/test_real_detonation.sh` against a Linux host with all lab binaries installed.
- Must produce a signed chain-of-custody manifest that `cosign verify` passes on.

### 7.4 Continuous integration

- GitHub Actions: unit + integration (no RUN_INTEGRATION_TESTS required for the non-live ones) on every PR.
- Nightly: `RUN_INTEGRATION_TESTS=1` on a Linux runner with docker-compose stack up.

---

## 8. Rollout plan

### 8.1 Pre-beta checklist

- [ ] All gaps in §3 closed OR explicitly deferred with sign-off.
- [ ] G1-G7 from §1 all pass.
- [ ] `tests/e2e/test_real_detonation.sh` green on a representative Ubuntu 24 host.
- [ ] `sheshnaag audit verify` green.
- [ ] No red tests in `pytest tests/` (including RUN_INTEGRATION_TESTS=1 outside the live-API-dependent ones).
- [ ] `docs/SHESHNAAG_V4_BETA_OPERATOR_RUNBOOK.md` walked by someone who did not write it.

### 8.2 Beta cohort

- Size: 5-10 trusted users.
- Onboarding: provide host-prep script + runbook + a dedicated Signal/Slack channel.
- Telemetry: opt-in OpenTelemetry export to a central collector under your control.

### 8.3 Rollback

- Every Alembic migration has a tested downgrade.
- Every release is tagged; revert to tag + `git push origin main --force-with-lease` only after cohort-wide comms.
- Signing key rotation runbook lives in `SHESHNAAG_V4_BETA_OPERATOR_RUNBOOK.md`.

---

## 9. Effort summary

Grouped, sized with 1 senior dev at ~80% focus:

| Work stream | Size | Parallelizable with |
|---|---|---|
| 3.1 UI surfaces (Auth / Run / ATT&CK / Graph + components) | 7-9 days | 3.2, 3.3, 3.4 backends |
| 3.2 ATT&CK mapping + routes | 4-5 days | 3.1, 3.3 |
| 3.3 Ops hardening (MinIO, Redis, Sigstore, logs, OTel, worker, health) | 7-9 days | 3.1 UI |
| 3.4 Autonomous Agent + page | 7-10 days | 3.5, 3.6 |
| 3.5 V3 → V4 upgrade | 1-2 days | everything else |
| 3.6 Production sandbox + E2E test | 2-3 days | 3.1 UI |
| 3.7 V3 test fix | 15 min | everything else |
| 3.8 Docs | 1-2 days | everything else |

**Serial total:** ~30-40 days.
**Parallel total (3 streams: UI, backend, ops):** ~15-18 days wall-clock.

**With ~3-4 weeks of focused work by one senior dev + occasional help from a frontend contractor, V4 hits beta-ready.** With one dev and no help, budget 5-6 weeks.

---

## 10. What you are explicitly NOT expected to do

These are GA-ward, not beta-ward. Do not scope-creep into them:

- Behavior-embedding similarity + variant diff (Phase G2)
- Detection-engineering copilot (Phase G3)
- NL hunt + scheduled AI threat briefs (Phase G4)
- Counterfactual runs, adversary emulator, AI self-red-team (Phase G5)
- Multi-host / Kubernetes / Nomad (V5)
- External IdP federation / OIDC SSO (V5)
- Cross-tenant federation (V5)
- Windows-kernel driver or UEFI analysis (V5+)

If a beta tester asks for one of these, log it and roll it into the V5 or GA planning. Do not ship it ad-hoc.

---

## 11. Contact the original authors

- Original V4 design authors: ArchFit (repo owner). Design rationale not captured elsewhere is in the PR #1 description.
- Parallel-agent dispatch history is in `.claude/plans/talk-to-me-what-iterative-teapot.md`.
- The "knock-it-out-the-park" prompt that kicked off all of V4 is referenced in the roadmap doc; treat it as the north-star statement of ambition.

If a design choice here seems wrong, it probably is — but check the PRD and architecture docs first, then ask. The capability policy (replacement for the V3 prompt blocklist) in particular is deliberately stricter than V3 despite enabling full-spectrum posture; do not weaken it without a written RFC.
