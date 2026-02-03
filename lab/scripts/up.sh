#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

docker compose -f "${ROOT_DIR}/lab/docker-compose.lab.yml" up -d db redis api
echo "Lab is starting..."
echo "API (host): http://127.0.0.1:18000"

