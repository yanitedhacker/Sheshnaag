#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="${SHESHNAAG_OSQUERY_IMAGE:-sheshnaag-kali-osquery:2026.1}"

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker CLI not available; cannot build ${IMAGE_TAG}."
  exit 0
fi

if ! docker version >/dev/null 2>&1; then
  echo "SKIP: docker daemon not available; cannot build ${IMAGE_TAG}."
  exit 0
fi

docker build \
  -t "${IMAGE_TAG}" \
  -f "${ROOT_DIR}/lab/images/osquery/Dockerfile" \
  "${ROOT_DIR}"
