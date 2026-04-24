# Project Sheshnaag — V4 PRD

**Status:** Draft (design approved; implementation pending)
**Supersedes:** `PROJECT_SHESHNAAG_PRD.md` for the V4 iteration. The V2/V3 PRD remains valid for the exposure-aware threat-radar and malware-lab skeletons that preceded this work.

---

## 1. One-line Vision

A **single-host-hardened, full-spectrum AI-enabled cybersec lab** that lets a small team run serious malware analysis, detection engineering, intel correlation, and authorized offensive research under a signed capability-policy regime — with an autonomous analyst agent that can drive a case end-to-end and hand a reviewer a finished report.

## 2. Why V4 Exists

V3 shipped a credible skeleton but three pillars were scaffolded rather than operational:

- **AI was stubbed** — the `openai-api` / `anthropic-api` adapters POST a custom body to a user-supplied URL; they don't speak `/v1/messages` or `/v1/chat/completions`. Default behavior is a grounded-markdown fallback marked `simulated_unconfigured`.
- **Detonation was synthetic** — `materialize_run_outputs` seeded DB rows with hardcoded confidence scores (0.84, 0.82, 0.88, 0.71); sandbox providers ran user-supplied commands, not the specimen. Egress modes, snapshots, and "fake internet" were metadata strings, not enforced runtime controls.
- **Intel + correlation were thin** — solid CVE pipeline (OSV/GHSA/KEV/EPSS/NVD), but no MISP, VirusTotal, OTX, abuse.ch, STIX/TAXII, or IOC↔finding↔CVE↔asset graph; no MITRE ATT&CK mapping.

V4 closes those three gaps, widens lab posture to **full-spectrum** (capability-based policy replacing the hard prompt blocklist), and adds four novel capability tracks that differentiate it from a Cuckoo-plus-AI wrapper.

## 3. Target User

**Primary:** Senior security analyst / detection engineer / malware researcher at a small in-house team, running their own box. Comfortable with Docker, familiar with Sigma/YARA/ATT&CK, reviews AI output rather than blindly trusting it.

**Secondary:**
- Reviewer / team lead who approves high-risk capability unlocks and external disclosures.
- Admin / operator who owns hardware, credentials, and policy versions.
- (Non-goal) Multi-tenant SaaS customer — V4 is single-tenant-per-host by design; horizontal scaling deferred to V5.

## 4. Confirmed Scope

### 4.1 Posture — **Full-spectrum cybersec lab**
- **Remove** the regex-based `BLOCKED_PROMPT_PATTERNS` in `app/services/ai_provider_harness.py`.
- **Replace** with an explicit **capability policy engine** + signed **authorization artifacts** per capability unlock.
- Every risky capability (exploit validation, red-team emulation, offensive research, external disclosure, specimen exfil, destructive defang) is named, gated, and time-boxed.
- Unsigned = blocked. All state in a Merkle-chained, append-only audit log.

### 4.2 AI providers — **All four families, first-class**
| Provider family | Native wire format | Streaming | Tool use | Prompt caching |
|---|---|---|---|---|
| Anthropic Claude | `/v1/messages` | SSE | Yes | Yes (ephemeral cache) |
| OpenAI | `/v1/chat/completions` | SSE | Function calling | No (provider-side) |
| Google Gemini | `v1beta/models/*:streamGenerateContent` | SSE | Function calling | N/A |
| Azure OpenAI | Resource URL + `api-version` + `api-key` | SSE | Function calling | No |
| AWS Bedrock | SigV4 + `InvokeModelWithResponseStream` | Yes | Per-model | Per-model |
| Local Ollama / vLLM | OpenAI-compatible | SSE | Per-model | No |

### 4.3 Deployment — **Single-host hardened**
Docker-compose with Postgres+pgvector, MinIO, Redis Streams, dedicated sandbox-worker process pool, systemd supervision. SQLite demoted to dev-only. Horizontal scaling, Kubernetes, Nomad, and distributed sandboxes are explicitly deferred to V5.

### 4.4 Novel Capabilities — **All four tracks ship, in priority order**
1. **Autonomous Analyst Agent** — end-to-end case execution under policy.
2. **Behavior-Embedding Similarity + Variant Diff** — neural fingerprint → pgvector ANN.
3. **Detection-Engineering Copilot** — AI drafts + validator + PR-style promote.
4. **NL Hunt + Scheduled AI Threat Briefs** — English-to-query + nightly digest.

Bonus novel features (counterfactual runs, adversary emulation, self-red-team, Sigstore-signed manifests) ship opportunistically.

## 5. Success Criteria

A V4 release is shippable when all of the following are true:

1. **Real AI, all four families** — with each of `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `AZURE_OPENAI_*`, `AWS_*`, and a local Ollama endpoint, an `/api/v3/ai/sessions` call returns non-fallback output, streams tokens, executes at least one policy-gated tool invocation, and hits prompt cache on repeat where supported.
2. **Real detonation** — benign test specimen (EICAR-class) produces: real container/VM boot with snapshot, egress confined to sinkhole, pcap > 5 s, Volatility 3 plugin output, Zeek logs, `BehaviorFinding` rows with non-synthetic confidence derived from telemetry. Specifically: **no hardcoded 0.84/0.82/0.88/0.71 values remain in `materialize_run_outputs`**.
3. **Capability policy** — without an authorization artifact, offensive-research actions are blocked. With a reviewer-signed artifact they are permitted and audit-logged. Revocation re-blocks immediately. The Merkle-chained audit log verifies independently.
4. **Intel fabric** — ingest a MISP feed; an IOC in an active case auto-enriches with VT + OTX + MalwareBazaar verdicts; STIX 2.1 bundle emitted on export; IOC pivot graph shows linked cases, specimens, CVEs, assets.
5. **ATT&CK** — `AttackCoveragePage` renders a heatmap of observed techniques; cells drill into contributing findings.
6. **UX** — `RunConsolePage` streams live SSE events; Case Graph renders specimen↔finding↔IOC↔CVE↔asset graph; AI sidebar opens the source documents used to ground a claim.
7. **Autonomous Analyst Agent** — submit a specimen; agent runs detonations + detections + report under policy; reviewer approves; signed chain-of-custody manifest verifies externally with `cosign`.
8. **Behavior similarity + variant diff** — upload two family variants; variant-diff report highlights behavioral delta and ATT&CK technique drift; similarity search from a third variant surfaces both.
9. **Detection copilot** — AI drafts a Sigma rule; validator reports FP/FN against the historical telemetry corpus; analyst promotes via PR-style flow; rule live in the Sigma artifact store.
10. **NL hunt + scheduled brief** — NL query round-trips to structured query and renders results; nightly AI threat brief lands in the configured Slack/email/Linear channel with intel + cases + ATT&CK drift.

## 6. Explicitly Out of Scope for V4

- Multi-host / Kubernetes / Nomad orchestration (→ V5).
- Multi-tenant SaaS — V4 remains single-tenant-per-host. Existing `tenants` table stays for namespacing but cross-tenant federation is deferred.
- Mobile (iOS/Android) specimen detonation — emulator integrations out of scope.
- Windows-kernel driver analysis, UEFI / firmware analysis — deferred.
- Hardware-side-channel (Spectre-class) research — out of scope.
- Production-grade identity broker / SSO — V4 keeps the existing JWT + scope/tenant model; external IdP federation deferred to V5.

## 7. Non-Functional Requirements

| Area | Requirement |
|---|---|
| **Availability** | Single-host; 99% monthly on the operator's own uptime. Graceful degradation when a provider family is unreachable. |
| **Latency** | AI streaming first token ≤ 2 s median for cloud providers; detonation run queue SLA ≤ 30 s at p95 to accept. |
| **Storage** | Postgres primary; MinIO for quarantine + reports; pgvector for embeddings and behavior fingerprints. |
| **Observability** | OpenTelemetry traces (API → service → sandbox); Prometheus `/metrics`; structured JSON logs everywhere. |
| **Security** | All authorization artifacts Sigstore/cosign-signed; audit log Merkle-chained and optionally published to Rekor; secrets only via env / Vault; no secrets in DB. |
| **Privacy** | PII scrubber at ingest (wire `aidefence` MCP as middleware); quarantined specimens never reach cloud AI providers unless the operator explicitly opts in via a capability unlock. |
| **Reproducibility** | Every run's manifest includes: specimen digest, profile digest, sandbox image digest, policy snapshot digest, AI model + prompt-cache digest. |

## 8. Risks

| Risk | Mitigation |
|---|---|
| Full-spectrum posture removes the soft blocklist — concern that the lab becomes misusable | Hard capability gates + signed authorization artifacts + Merkle-chained audit log + reviewer sign-off for risky capabilities. Safety story is **stronger**, not weaker. |
| Real detonation introduces host-level risk | Egress enforced at nftables kernel level; snapshots mandatory; network fully isolated; quarantine in MinIO with signed manifests. |
| Cloud AI providers may see analyst prompts / specimens | Local (Ollama/vLLM) provider family is first-class; operator can route sensitive workloads locally via policy. Grounding is always mandatory. |
| Single-host cap limits scale | Accepted; V5 introduces worker-fleet horizontal scaling. |
| Scope breadth (8 pillars + 4 novel tracks) | Phased delivery (A → G5); each phase independently reviewable; GSD workflow enforces atomic commits and Nyquist validation. |

## 9. Success = User Experience

A senior analyst arrives at the lab with a new specimen in the morning. By lunch, the Autonomous Analyst Agent has:

- quarantined it, chosen the right sandbox profile, detonated it in a snapshot-backed VM with egress sinkholed;
- collected pcap, memory, eBPF syscalls, Volatility plugin output;
- tagged ATT&CK techniques on each finding;
- auto-enriched IOCs with VT + OTX verdicts;
- found three behavioral siblings via pgvector similarity and produced a variant-diff report;
- drafted Sigma + YARA rules and validated them against the telemetry corpus (7% FP, 0% FN on ground truth);
- produced a STIX 2.1 bundle and a PDF report;
- signed the chain-of-custody manifest with cosign.

The analyst opens the Autonomous Agent page, reviews the trace, clicks approve. The reviewer's sign-off appears in the Merkle audit log. Done. That's the V4 success shape.
