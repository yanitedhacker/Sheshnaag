#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

docker compose -f "${ROOT_DIR}/lab/docker-compose.lab.yml" exec -T api python scripts/init_db.py

