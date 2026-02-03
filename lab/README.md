# CVE Threat Radar — Testing Lab

This directory provides a dedicated testing lab for:
- **Unit tests** (fast, local)
- **Integration tests** (Docker: Postgres + Redis + API)
- **Load tests** (Locust profiles)

## Unit tests (local)

From repo root:

```bash
./venv/bin/python -m pytest -m unit
```

## Integration tests (Docker-first)

From repo root:

```bash
./lab/scripts/up.sh
./lab/scripts/seed.sh
./lab/scripts/pytest.sh
./lab/scripts/down.sh
```

Notes:
- Host API is exposed at `http://127.0.0.1:18000`.
- DB is exposed at `127.0.0.1:15432` (Postgres).
- Redis is exposed at `127.0.0.1:16379`.

## Load tests (Locust)

From repo root:

```bash
docker compose -f ./lab/docker-compose.lab.yml run --rm locust
```

Outputs are written to `lab/results/`.

