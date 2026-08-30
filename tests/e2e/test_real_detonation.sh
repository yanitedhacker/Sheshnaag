#!/usr/bin/env bash
# Fail-closed Linux/KVM detonation proof harness.
set -euo pipefail
umask 077

API="${SHESHNAAG_API:-http://127.0.0.1:8000}"
ACCESS_TOKEN="${SHESHNAAG_ACCESS_TOKEN:-}"
TENANT_SLUG="${SHESHNAAG_TENANT:-}"
RECIPE_ID="${SHESHNAAG_RECIPE_ID:-}"
TIMEOUT="${SHESHNAAG_TIMEOUT:-300}"
KVM_DEVICE="${SHESHNAAG_KVM_DEVICE:-/dev/kvm}"
LIBVIRT_URI="${SHESHNAAG_LIBVIRT_URI:-qemu:///system}"
RETAINED_OUTPUT="${SHESHNAAG_E2E_OUTPUT_DIR:-}"

log() { printf '[real_detonation] %s\n' "$*"; }
fail_preflight() { log "FAIL: $*"; exit 2; }
fail_proof() { log "FAIL: $*"; exit 1; }

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail_preflight "required tool not found: $1"
}

[[ -n "${ACCESS_TOKEN}" ]] || fail_preflight "SHESHNAAG_ACCESS_TOKEN is required"
[[ -n "${TENANT_SLUG}" ]] || fail_preflight "SHESHNAAG_TENANT is required"
[[ "${TENANT_SLUG}" != "demo-public" ]] || fail_preflight "demo-public is read-only"
[[ "${RECIPE_ID}" =~ ^[1-9][0-9]*$ ]] || fail_preflight "SHESHNAAG_RECIPE_ID must be a positive integer"
[[ "${TIMEOUT}" =~ ^[1-9][0-9]*$ ]] || fail_preflight "SHESHNAAG_TIMEOUT must be a positive integer"
[[ "$(uname -s)" == "Linux" ]] || fail_preflight "Linux is required"
[[ -r "${KVM_DEVICE}" && -w "${KVM_DEVICE}" ]] || fail_preflight "KVM device is not readable and writable: ${KVM_DEVICE}"

for tool in curl jq virsh zeek git grep; do
  require_tool "${tool}"
done

if command -v sha256sum >/dev/null 2>&1; then
  CHECKSUM_COMMAND=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  CHECKSUM_COMMAND=(shasum -a 256)
else
  fail_preflight "sha256sum or shasum is required"
fi

virsh -c "${LIBVIRT_URI}" list --all >/dev/null 2>&1 \
  || fail_preflight "virsh cannot list domains through ${LIBVIRT_URI}"

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT
if [[ -n "${RETAINED_OUTPUT}" ]]; then
  EVIDENCE_DIR="${RETAINED_OUTPUT}"
else
  EVIDENCE_DIR="${TEMP_DIR}/evidence"
fi
mkdir -p "${EVIDENCE_DIR}"

AUTH_HEADER=(--header "Authorization: Bearer ${ACCESS_TOKEN}")

redact_json_file() {
  local source_file="$1"
  local redacted_file="${source_file}.redacted"
  jq 'walk(if type == "object" then del(.access_token, .refresh_token, .token, .secret) else . end)' \
    "${source_file}" > "${redacted_file}" \
    || fail_proof "invalid JSON response for $(basename "${source_file}")"
  mv "${redacted_file}" "${source_file}"
}

request_json() {
  local output_file="$1"
  shift
  curl -fsS "${AUTH_HEADER[@]}" "$@" > "${output_file}" \
    || fail_proof "HTTP request failed for $(basename "${output_file}")"
  redact_json_file "${output_file}"
}

OPS_FILE="${EVIDENCE_DIR}/ops-health.json"
log "Checking API and secure runtime health"
request_json "${OPS_FILE}" --max-time 10 "${API}/api/ops/health"
jq -e '
  .api == "ok" and
  .lab_deps.kvm == "ok" and
  .lab_deps.virsh == "ok" and
  .lab_deps.zeek == "ok" and
  .detonation_runtime.egress_enforce == "on" and
  .detonation_runtime.pcap == "on"
' "${OPS_FILE}" >/dev/null || fail_preflight "API secure runtime health is blocked"

SAMPLE_FILE="${TEMP_DIR}/eicar.txt"
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
printf '%s' "${EICAR}" > "${SAMPLE_FILE}"

SPECIMEN_FILE="${EVIDENCE_DIR}/specimen.json"
log "Uploading benign EICAR-class specimen bytes"
request_json "${SPECIMEN_FILE}" \
  --request POST "${API}/api/specimens/upload" \
  --form "tenant_slug=${TENANT_SLUG}" \
  --form "name=EICAR proof sample" \
  --form "specimen_kind=file" \
  --form "submitted_by=real-detonation-harness" \
  --form "summary=Benign proof payload" \
  --form "labels=[\"proof-harness\"]" \
  --form "metadata={\"source\":\"tests/e2e/test_real_detonation.sh\"}" \
  --form "file=@${SAMPLE_FILE};type=application/octet-stream"
SPECIMEN_ID="$(jq -er '.id | select(type == "number")' "${SPECIMEN_FILE}")" \
  || fail_proof "specimen response has no numeric id"
jq -e '.latest_revision.sha256 | strings | test("^[0-9a-f]{64}$")' \
  "${SPECIMEN_FILE}" >/dev/null || fail_proof "specimen response has no SHA-256 digest"

CASE_FILE="${EVIDENCE_DIR}/case.json"
CASE_BODY="$(jq -nc \
  --arg slug "${TENANT_SLUG}" \
  --argjson specimen_id "${SPECIMEN_ID}" \
  '{tenant_slug:$slug,title:"Real detonation proof",analyst_name:"real-detonation-harness",summary:"Commit-bound Linux KVM proof",priority:"high",specimen_ids:[$specimen_id],tags:["proof-harness"]}')"
log "Creating analysis case"
request_json "${CASE_FILE}" \
  --request POST "${API}/api/analysis-cases" \
  --header 'Content-Type: application/json' \
  --data "${CASE_BODY}"
CASE_ID="$(jq -er '.id | select(type == "number")' "${CASE_FILE}")" \
  || fail_proof "case response has no numeric id"

RUN_FILE="${EVIDENCE_DIR}/launch.json"
RUN_BODY="$(jq -nc \
  --arg slug "${TENANT_SLUG}" \
  --argjson recipe_id "${RECIPE_ID}" \
  --argjson specimen_id "${SPECIMEN_ID}" \
  '{tenant_slug:$slug,recipe_id:$recipe_id,analyst_name:"real-detonation-harness",launch_mode:"execute",acknowledge_sensitive:true,analysis_mode:"malware_detonation",specimen_ids:[$specimen_id],egress_mode:"sinkhole",workstation:{hostname:"linux-kvm-worker",os_family:"Linux",architecture:"x86_64",fingerprint:"real-detonation-harness"}}')"
log "Launching execute-mode run for case_id=${CASE_ID}"
request_json "${RUN_FILE}" \
  --request POST "${API}/api/runs" \
  --header 'Content-Type: application/json' \
  --data "${RUN_BODY}"
RUN_ID="$(jq -er '.id | select(type == "number")' "${RUN_FILE}")" \
  || fail_proof "run response has no numeric id"
jq -e '.provider == "libvirt"' "${RUN_FILE}" >/dev/null \
  || fail_proof "run did not route to libvirt"

FINAL_RUN_FILE="${EVIDENCE_DIR}/final-run.json"
log "Polling run_id=${RUN_ID}"
deadline=$((SECONDS + TIMEOUT))
state=""
while (( SECONDS <= deadline )); do
  request_json "${FINAL_RUN_FILE}" \
    --max-time 10 "${API}/api/runs/${RUN_ID}?tenant_slug=${TENANT_SLUG}"
  state="$(jq -er '.state | strings' "${FINAL_RUN_FILE}")" \
    || fail_proof "run response has no state"
  case "${state}" in
    completed) break ;;
    queued|planned|booting|ready|running) sleep 2 ;;
    *) fail_proof "run reached terminal state ${state}" ;;
  esac
done
[[ "${state}" == "completed" ]] \
  || fail_proof "run did not complete within ${TIMEOUT}s; last state=${state}"

jq -e '
  .provider == "libvirt" and
  .manifest.detonation_preflight.status == "ok" and
  .manifest.worker_execution.status == "completed" and
  (.manifest.worker_execution.live_evidence_count | type == "number" and . >= 1) and
  ([.timeline[].event_type] | contains(["run_queued", "run_started", "run_completed"]))
' "${FINAL_RUN_FILE}" >/dev/null || fail_proof "final run is missing required completion proof"

EVIDENCE_FILE="${EVIDENCE_DIR}/evidence.json"
request_json "${EVIDENCE_FILE}" \
  --max-time 10 "${API}/api/evidence?tenant_slug=${TENANT_SLUG}&run_id=${RUN_ID}"
jq -e --argjson run_id "${RUN_ID}" '
  (.count | type == "number" and . >= 1) and
  ([.items[] | select(.run_id == $run_id)] | length >= 1)
' "${EVIDENCE_FILE}" >/dev/null || fail_proof "evidence API returned no item for the run"

SSE_FILE="${EVIDENCE_DIR}/events.sse"
sse_status=0
curl -fsS --max-time 8 "${AUTH_HEADER[@]}" \
  "${API}/api/v4/runs/${RUN_ID}/events?tenant_slug=${TENANT_SLUG}&last_id=0-0" \
  > "${SSE_FILE}" || sse_status=$?
if (( sse_status != 0 && sse_status != 28 )); then
  fail_proof "SSE replay request failed with curl status ${sse_status}"
fi
grep -Eq 'data:.*"type"[[:space:]]*:[[:space:]]*"run_completed"' "${SSE_FILE}" \
  || fail_proof "SSE replay has no run_completed event"

REPO_ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")/../.." rev-parse --show-toplevel)"
git -C "${REPO_ROOT}" rev-parse HEAD > "${EVIDENCE_DIR}/git-commit.txt"
(
  cd "${EVIDENCE_DIR}"
  "${CHECKSUM_COMMAND[@]}" \
    ops-health.json specimen.json case.json launch.json final-run.json \
    evidence.json events.sse git-commit.txt > manifest.sha256
)

log "PASS: real detonation proof completed run_id=${RUN_ID} state=${state}"
if [[ -n "${RETAINED_OUTPUT}" ]]; then
  log "Evidence retained at ${EVIDENCE_DIR}"
fi
