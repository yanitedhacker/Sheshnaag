# V6 Smoke Runbook

End-to-end dry run for the V6 milestone on the 3-node deployment (1 control plane + 2 KVM workers).

## Prerequisites

- V5 gate signed: [docs/runbooks/v5/gate-signoff.md](../v5/gate-signoff.md)
- Control plane: API on `:8000`, Postgres, Redis loopback
- Workers: `sheshnaag-wk-01` / `sheshnaag-wk-02` with libvirt + golden image `sheshnaag-windows-golden`
- Migrations through `v6a02` applied

## Steps

### 1. Adversary harness (gate item 1 — policy chokepoint)

```bash
pytest tests/red_team/test_capability_escapes.py -q
pytest tests/v6/test_auth_issue_enforcement.py -q
```

Expect: 0 escapes; analyst denied for `offensive_research`; single reviewer rejected for dual capabilities.

### 2. Authorization Center quorum (gate item 5)

Manual on **Authorization Center** (`/authorization`):

1. As `senior_analyst`, request `exploit_validation` with two distinct reviewers → artifact `active`.
2. As `analyst`, confirm request button disabled for offensive capabilities.
3. Attempt self-approval → API rejects with `requester_cannot_review`.

### 3. Windows libvirt detonation (gate item 2)

```bash
pytest tests/v6/test_libvirt_provider.py -q
```

Manual on `sheshnaag-wk-01`:

```bash
export SHESHNAAG_WINDOWS_IMAGE=sheshnaag-windows-golden
export SHESHNAAG_LIBVIRT_URI=qemu:///system
# Run a Windows recipe via Run Console — provider=libvirt, launch_mode=execute
```

Verify: Sysmon + ETW artifacts in run bundle; signed export digest matches Linux baseline shape.

### 4. Exploit validation attestation (gate item 4)

```bash
pytest tests/v6/test_exploit_validator.py -q
```

API smoke:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v6/exploit-validation/runs \
  -H "Authorization: Bearer $SIGNED_JWT" \
  -H "Content-Type: application/json" \
  -d '{"cve_id":"CVE-2024-0001","vulnerable_image_digest":"sha256:vuln","patched_image_digest":"sha256:patch","scope":{"poc_body":"print(1)"}}' | jq .
```

Expect: non-empty `manifest_digest`.

### 5. Purple team ≥80 techniques (gate item 3)

```bash
pytest tests/v6/test_purple_team.py -q
```

Manual: **Purple Team** page → Run replay → coverage gap shows `meets_gate_80: true`.

### 6. Offensive research workbench

```bash
pytest tests/v6/test_offensive_research.py -q
```

Manual: **Research Workbench** → fuzz target → triage crash verdict renders.

### 7. Full V6 suite

```bash
pytest tests/v6/ tests/red_team/test_capability_escapes.py -q
```

## Artifacts

Store proof under `data/release_metadata/v6-gate/`:

- `adversary-harness.log`
- `windows-detonation-manifest.json`
- `exploit-validation-manifest.json`
- `purple-team-gap.json`
- `authorization-quorum-screenshot.png` (optional)
