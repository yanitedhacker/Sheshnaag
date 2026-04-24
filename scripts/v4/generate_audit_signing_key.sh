#!/usr/bin/env bash
# Generate the HMAC dev key used by HmacDevSigner OR write a placeholder for
# Sigstore deployments where the real key material is held by the OIDC
# identity provider (Fulcio short-lived certificates).
#
# Usage:
#   scripts/v4/generate_audit_signing_key.sh hmac > audit_signing.key
#   scripts/v4/generate_audit_signing_key.sh cosign > audit_signing.notes
set -euo pipefail

mode="${1:-hmac}"

case "${mode}" in
  hmac)
    if ! command -v openssl >/dev/null 2>&1; then
      echo "openssl is required to generate an HMAC key" >&2
      exit 2
    fi
    # 32 random bytes, hex-encoded — set as AUDIT_SIGNING_KEY in env.
    openssl rand -hex 32
    ;;
  cosign)
    cat <<'NOTES'
Sigstore (cosign) does NOT use a long-lived local key.
Set SHESHNAAG_AUDIT_SIGNER=cosign and ensure:
  - The host has network access to Fulcio (https://fulcio.sigstore.dev) and
    Rekor (https://rekor.sigstore.dev), OR private equivalents via
    SIGSTORE_FULCIO_URL / SIGSTORE_REKOR_URL.
  - An OIDC identity is available (workload identity, GitHub OIDC, Google
    workload identity, or a static OIDC token via SIGSTORE_ID_TOKEN).
  - The 'sigstore>=3' Python package is installed.
Cosign issues a short-lived signing certificate per call and publishes the
signature to Rekor for transparency. The local audit chain still detects
tampering, and the Rekor entry provides an externally verifiable timestamp.
NOTES
    ;;
  *)
    echo "Unknown mode: ${mode} (expected hmac or cosign)" >&2
    exit 2
    ;;
esac
