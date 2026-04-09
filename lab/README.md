# Project Sheshnaag Testing Lab

This directory provides a dedicated testing lab for:
- **Unit tests** (fast, local)
- **Integration tests** (Docker: Postgres + Redis + API)
- **Execute-mode smoke tests**
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

## Execute-mode smokes

From repo root:

```bash
python scripts/sheshnaag_execute_smoke.py
bash scripts/build_sheshnaag_osquery_image.sh
python scripts/sheshnaag_osquery_smoke.py
```

Notes:
- `scripts/sheshnaag_execute_smoke.py` validates the baseline execute-mode lab path when Docker is available.
- `scripts/sheshnaag_osquery_smoke.py` validates live `osquery_snapshot` capture against the dedicated osquery-capable image.
- The smoke commands self-skip when Docker or the required image is unavailable, so they can stay in the rehearsal workflow without breaking non-Docker development.

## Load tests (Locust)

From repo root:

```bash
docker compose -f ./lab/docker-compose.lab.yml run --rm locust
```

Outputs are written to `lab/results/`.
