#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

set -a
source "${ROOT_DIR}/lab/locust/profiles/smoke.env"
set +a

docker compose -f "${ROOT_DIR}/lab/docker-compose.lab.yml" run --rm \
  -e LOCUST_HOST="http://api:8000" \
  locust \
  -f /mnt/locust/locustfile.py \
  --headless \
  -u "${LOCUST_USERS}" -r "${LOCUST_SPAWN_RATE}" \
  -t "${LOCUST_RUN_TIME}" \
  --csv /mnt/results/smoke

