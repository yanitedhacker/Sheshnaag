# Project Sheshnaag — V4 Capability Policy

**Status:** Draft (design approved; implementation pending)
**Supersedes:** the regex-based `BLOCKED_PROMPT_PATTERNS` list in `app/services/ai_provider_harness.py` and the soft blocklist referenced in `SHESHNAAG_SAFETY_POLICY.md`.

---

## 1. Why This Document Exists

V3's safety story was a **regex prompt blocklist**: any prompt containing "weaponize", "exploit chain", "phishing", "credential dumping", etc. was rejected. This is a porous defense — easy to bypass with paraphrase, easy to trip on legitimate defensive work ("we need to detect phishing") — and it couples the lab's safety posture to a fragile string match.

V4 ships a **full-spectrum cybersec lab**. That expanded posture is not achieved by relaxing safety; it is achieved by replacing the soft blocklist with **hard capability gates**, **signed authorization artifacts**, a **Merkle-chained audit log**, and **multi-reviewer sign-off** for the riskiest operations.

**Net effect: the V4 safety story is stronger than V3's, not weaker.** V3 trusted a regex. V4 requires a signed, scoped, time-bound authorization artifact before any risky capability is usable, and every action is cryptographically accountable.

---

## 2. Capability Taxonomy

Every risky action the system can perform is named as a **capability**. Capabilities are coarse enough to be reviewed (a human can grasp them), fine enough to be useful (different actions get different unlock paths), and versioned (the set evolves with the lab).

### 2.1 Core capabilities (ship in Phase A)

| Capability | Meaning | Default | Review path |
|---|---|---|---|
| `dynamic_detonation` | Execute a specimen inside a sandbox (VM / container) with enforced egress. | Admin-enabled per tenant | Single reviewer |
| `external_disclosure` | Emit a bundle (STIX / MISP / PDF) to an external party or TAXII collection. | Off | **Two reviewers** + tenant admin |
| `specimen_exfil` | Copy a raw specimen out of the quarantine store. | Off | Two reviewers + legal/admin |
| `destructive_defang` | Irreversibly modify stored evidence (redaction, irrecoverable defang). | Off | Two reviewers |
| `cloud_ai_provider_use` | Send grounding or prompts to a non-local AI provider (Anthropic / OpenAI / Gemini / Azure / Bedrock). | Per-tenant default | Single reviewer |
| `autonomous_agent_run` | Allow the Autonomous Analyst Agent to execute a case end-to-end. | Off | Single reviewer |

### 2.2 Full-spectrum capabilities (ship in Phase B / F)

| Capability | Meaning | Default | Review path |
|---|---|---|---|
| `exploit_validation` | Run a PoC exploit against an isolated target in the lab (full-spectrum). | Off | **Two reviewers** + signed engagement authorization |
| `red_team_emulation` | Execute adversary-emulation recipes that mimic offensive TTPs. | Off | Two reviewers + signed engagement authorization |
| `offensive_research` | Authoring / executing offensive tooling beyond emulation (exploit dev, fuzzer harnesses, custom implants). | Off | **Two reviewers + admin + signed engagement authorization + expiry ≤ 7 days** |
| `network_egress_open` | Run with unrestricted egress (no sinkhole, no allowlist). | Off | Two reviewers + admin + expiry ≤ 24 h |
| `memory_exfil_to_host` | Pull guest memory dump onto the host for Volatility analysis. | Admin-enabled | Single reviewer |
| `kernel_driver_load` | Load a kernel module inside the sandbox (VM only). | Off | Two reviewers + signed engagement authorization |

Capabilities are declared in `app/services/capability_policy.py` as a frozen registry; adding one is a code change + migration, never an env override.

---

## 3. Authorization Artifact

A capability is usable only when a **valid authorization artifact** is present. An artifact is a signed JSON document:

```jsonc
{
  "artifact_id": "auth_01HZ2X7QK3M8ABCD",
  "schema_version": "v4.1",
  "capability": "offensive_research",
  "scope": {
    "tenant_id": 1,
    "case_ids": [42],
    "specimen_ids": [173],
    "profile_ids": ["hardened_kali"],
    "max_runs": 5,
    "network_profiles": ["isolated_lab"]
  },
  "requester": {
    "analyst": "alice@example.com",
    "reason": "Authorized engagement XYZ-2026-04 with written client scope attached",
    "engagement_ref": "engagements/2026/xyz/authorization.pdf.sha256=..."
  },
  "reviewers": [
    { "reviewer": "bob@example.com",   "decision": "approve", "signed_at": "2026-04-24T10:02:11Z" },
    { "reviewer": "carol@example.com", "decision": "approve", "signed_at": "2026-04-24T10:07:43Z" }
  ],
  "issued_at": "2026-04-24T10:08:02Z",
  "expires_at": "2026-04-25T10:08:02Z",
  "nonce": "b8f1...",
  "previous_audit_hash": "e2c9...",
  "sig": {
    "alg": "cosign-sigstore",
    "cert_chain": "...",
    "signature": "MEUCIQD..."
  }
}
```

### 3.1 Issuance flow

1. Analyst opens **AuthorizationCenterPage**, picks a capability, fills scope + reason + engagement reference.
2. Request lands in the reviewer queue. Reviewers sign `{decision: approve, signed_at}`.
3. For capabilities requiring two reviewers (see §2), both must approve.
4. On final approval, the server constructs the artifact, includes the current audit log root as `previous_audit_hash`, and signs with Sigstore/cosign (keyless or key-based).
5. Artifact is stored in `authorization_artifacts` and appended to the Merkle audit log.
6. The artifact is now usable until `expires_at` or explicit revocation.

### 3.2 Evaluation flow

Every risky action calls `capability_policy.evaluate(capability, scope, actor)`:

- Find the most specific **unexpired, unrevoked** artifact matching `(capability, scope, actor)`.
- If none → deny; emit a `CapabilityDenied` event to the audit log.
- If found → permit; emit a `CapabilityExercised` event referencing the artifact.

Evaluation is **read-only** w.r.t. the artifact (no mutation on use); the audit log carries the receipt.

### 3.3 Revocation

Admin or either original reviewer can revoke by issuing a signed `revoke` entry referencing `artifact_id`. The audit log carries the revocation. Subsequent evaluations deny; in-flight tool invocations bound to the artifact are allowed to complete but cannot start new steps.

### 3.4 Expiry defaults

Conservative defaults, overridable downward but never upward:

| Capability | Max TTL |
|---|---|
| `offensive_research` | 7 days |
| `network_egress_open` | 24 hours |
| `external_disclosure` | 72 hours |
| `exploit_validation`, `red_team_emulation` | 14 days |
| others | 30 days |

No artifact ever lives indefinitely.

---

## 4. Merkle-Chained Audit Log

All capability-policy activity lands in `audit_log_entries`. Each row:

```
idx                bigint   PRIMARY KEY
previous_hash      bytea    (hash of prior row; root for idx=0)
entry_hash         bytea    (sha256 of canonical JSON of this row's body)
actor              text     (analyst or system)
action             text     (issue | approve | revoke | exercise | deny)
capability         text
artifact_id        text     nullable
scope              jsonb
payload            jsonb    (action-specific context)
signed_at          timestamptz
signer_cert        bytea    nullable (for cosign-signed entries)
```

**Append-only**: enforced by a Postgres trigger rejecting UPDATE/DELETE on the table (a row may only INSERT).

**Chain integrity**: `entry_hash[i] = sha256(previous_hash[i] || canonical(body[i]))`. Any corruption is detectable by re-walking the chain.

**External verifiability** (optional): periodic Merkle tree root anchored to Rekor via the Sigstore transparency log. Gives independent auditors a check that the lab's audit chain has not been rewritten.

**Verification CLI**: `sheshnaag audit verify [--since=…]` re-walks the chain and re-verifies each entry's signature. Exit code ≠ 0 on failure.

---

## 5. Multi-Reviewer Sign-off

Capabilities flagged **Two reviewers** cannot be exercised with only a single approving reviewer — the artifact refuses to be issued. A tenant admin counts as a reviewer but the **requester can never also review**.

For `offensive_research` and `kernel_driver_load`, a **written engagement authorization** (PDF / document / signed email) must be attached, and its SHA-256 embedded in the artifact's `requester.engagement_ref`. The system does not parse the attachment; it records its digest for downstream audit.

---

## 6. UI Surfaces

### AuthorizationCenterPage (new, `frontend/src/pages/AuthorizationCenterPage.tsx`)

- Table of authorization artifacts with filter by capability / state / expiry.
- Issuer form with capability-aware scope fields.
- Reviewer inbox with signed-approve / signed-reject.
- Revocation UI.
- Verification panel showing the latest Merkle root and Rekor anchor (if configured).

### CapabilityGate component

Anywhere in the UI where a button triggers a capability-gated action, wrapping it in `<CapabilityGate capability="external_disclosure">` produces:
- If permitted: the normal button.
- If denied: a disabled button with a tooltip explaining **which capability is needed**, **what scope**, **and a one-click link to request an authorization artifact**.

This turns denials into guided next steps, not dead ends.

---

## 7. Code Shape

### `app/services/capability_policy.py`

```python
@dataclass(frozen=True)
class Capability:
    name: str
    default: Literal["off", "admin_per_tenant", "tenant_default"]
    review_kind: Literal["single", "dual", "dual_plus_admin"]
    max_ttl: timedelta
    requires_engagement_doc: bool = False

CAPABILITIES: dict[str, Capability] = {...frozen registry...}

class CapabilityPolicy:
    def evaluate(self, *, capability: str, scope: dict, actor: str) -> Decision: ...
    def issue(self, request: IssuanceRequest, reviewers: list[Reviewer]) -> AuthorizationArtifact: ...
    def revoke(self, artifact_id: str, actor: str, reason: str) -> None: ...
    def latest_root(self) -> MerkleRoot: ...
    def verify_chain(self, *, since: Optional[int] = None) -> VerificationResult: ...
```

### Integration points

- Every tool in `ai_tools_registry.py` declares its `capability: str | None`.
- Every risky API route wraps its handler with `Depends(require_capability("…"))`.
- Every launcher dispatch in `materialize_run_outputs` evaluates `dynamic_detonation` (and additional capabilities for destructive profiles).
- `ScopePolicy` (existing, per-tenant) stays; it now declares which capabilities have a `tenant_default` pre-authorization vs. which require explicit artifacts.

---

## 8. Relationship to Existing V3 Artifacts

| V3 surface | V4 treatment |
|---|---|
| `BLOCKED_PROMPT_PATTERNS` regex | **Removed.** Safety moves to capability gates. |
| Grounding validator (1–25 items, required) | **Kept.** Grounding is a correctness requirement, not a safety one. |
| `ScopePolicy` (per-tenant) | **Kept and extended.** Names which capabilities a tenant has as `tenant_default` (no artifact needed) vs. which require explicit issuance. |
| `review_queue_items` | **Extended.** Reviewer inbox now also carries authorization-artifact issuance requests. |
| `require_human_review_for_ai` | **Kept.** AI drafts still require review before promotion; orthogonal to capability policy. |
| `provenance_signatures` field on `MalwareReport` | **Kept.** Now populated by the Sigstore signer that also signs authorization artifacts. |

---

## 9. Testing and Verification

### Unit
- `test_capability_policy_denies_without_artifact`
- `test_capability_policy_permits_with_valid_artifact`
- `test_capability_policy_denies_expired_artifact`
- `test_capability_policy_denies_revoked_artifact`
- `test_capability_policy_denies_self_review`
- `test_capability_policy_enforces_dual_review`

### Audit chain
- `test_audit_chain_append_only` (Postgres trigger rejects UPDATE/DELETE)
- `test_audit_chain_hash_integrity` (rewalk detects corruption)
- `test_audit_chain_rekor_anchor_roundtrip` (optional, requires Rekor)

### End-to-end acceptance
1. Attempt `POST /api/v4/runs?profile=offensive_research` without artifact → `403 capability_required`, audit entry `deny`.
2. Issue signed artifact with two reviewers → artifact appears in `AuthorizationCenterPage` as `active`.
3. Re-attempt the run → `200`, audit entry `exercise` referencing artifact_id.
4. Revoke → audit entry `revoke` → re-attempt denies again.
5. `sheshnaag audit verify` succeeds; all entries' signatures valid; Merkle chain consistent.
6. Tamper with a row in `audit_log_entries` (DBA operation) → verification fails at that index.

---

## 10. Why This Is a Net Safety Gain

| Property | V3 blocklist | V4 capability policy |
|---|---|---|
| Bypass by paraphrase | Easy | Impossible — capability name is structural, not textual |
| False positives on defensive work | Common (e.g. "detect phishing") | None |
| Accountability for who did what | Weak (logs, maybe) | Signed, Merkle-chained, cosign-verified |
| Scope bounding | None | Per-artifact scope + expiry |
| Reviewer involvement | None | One or two reviewers per capability |
| Revocation | None | First-class; takes effect immediately |
| External auditability | None | Optional Rekor anchor |
| Does it expand the lab's reach? | No | Yes (full-spectrum); reach is gated per capability |

V4's safety is **harder to bypass, harder to misuse, and easier to audit** than V3's. The wider capability surface is possible because each risky capability carries its own cryptographic permission slip.
