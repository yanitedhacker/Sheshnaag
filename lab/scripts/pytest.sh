#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Runs init_db + pytest inside a disposable container.
docker compose -f "${ROOT_DIR}/lab/docker-compose.lab.yml" run --rm pytest

