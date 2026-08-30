# Real Detonation Proof Harness Design

**Status:** Approved for implementation by the repository owner on 2026-08-30.

## Objective

Replace the obsolete real-detonation script with a fail-closed operator harness
that uses the current authenticated API and can produce a commit-bound evidence
bundle for the existing proof-receipt tool.

## Current failure

The script defaults to the read-only demo tenant, creates metadata without
uploading specimen bytes, sends fields that the current specimen and run models
do not accept, does not identify an approved recipe, does not send a Bearer
token, and only warns when the completion event is absent. It can therefore
print `PASS` without proving the claimed path.

## Inputs

The harness requires these operator-owned values:

- `SHESHNAAG_ACCESS_TOKEN`: valid JWT for a writable private tenant;
- `SHESHNAAG_TENANT`: private tenant slug, never `demo-public`;
- `SHESHNAAG_RECIPE_ID`: approved recipe that is valid for execute mode;
- `SHESHNAAG_API`: API URL, default `http://127.0.0.1:8000`;
- `SHESHNAAG_TIMEOUT`: bounded run timeout, default `300` seconds;
- `SHESHNAAG_E2E_OUTPUT_DIR`: optional retained evidence directory.

The script generates a benign EICAR-class file, uploads the actual bytes with
`POST /api/specimens/upload`, creates an analysis case with the current schema,
and launches a current `RunLaunchRequest` with `launch_mode=execute`,
`analysis_mode=malware_detonation`, the specimen id, and sensitive-action
acknowledgement.

## Preflight

Before mutation, the harness fails unless:

- the local host is Linux;
- `/dev/kvm` exists and is readable and writable;
- `curl`, `jq`, `virsh`, and `zeek` are available;
- `virsh -c ${SHESHNAAG_LIBVIRT_URI:-qemu:///system} list --all` succeeds;
- API health is reachable;
- ops health reports KVM, `virsh`, and Zeek as `ok`;
- egress enforcement and PCAP capture are `on`;
- the tenant is private and the access token is present.

## Pass contract

The harness exits zero only when all of these statements are true:

- specimen upload returned a numeric id and a SHA-256 digest;
- case creation returned a numeric id;
- run launch returned a numeric id and provider `libvirt`;
- the run reached `completed` before the timeout;
- `manifest.detonation_preflight.status` is `ok`;
- `manifest.worker_execution.status` is `completed`;
- `manifest.worker_execution.live_evidence_count` is at least one;
- the run timeline contains `run_queued`, `run_started`, and `run_completed`;
- the evidence API returns at least one item for this run;
- the SSE replay contains a `run_completed` event.

Any missing field, HTTP error, terminal error state, timeout, or missing event is
a failure. There are no warning-only proof conditions.

## Evidence output

The retained directory contains redacted JSON responses for ops health,
specimen, case, launch, final run, evidence, and SSE output, plus a manifest with
the current Git commit and SHA-256 digests for every file. The access token is
never written to disk or printed.

## Verification

Automated tests execute the script against controlled fake command binaries.
They prove that missing credentials, demo tenant use, missing KVM, and missing
completion evidence fail, and that the complete current-API flow succeeds.
The real Linux/KVM run remains an external qualification gate.
