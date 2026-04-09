# Sheshnaag v2 Deployment Guide

Last updated: 2026-04-09

## Supported topology

The supported v2 deployment target is a single small-team server running:

- `frontend`
- `api`
- `postgres`
- `redis`
- `prometheus`

Deployment is packaged with `docker-compose.yml` and uses `.env.server.example` as the starting point.

## Bring-up

1. Copy `.env.server.example` to `.env`.
2. Set `SECRET_KEY`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `ALLOWED_ORIGINS`, and `SIGNING_KEY_DIR`.
3. Create the signing-key mount path and protect it with host filesystem permissions.
4. Start the stack with `docker compose up --build -d`.
5. Verify `http://127.0.0.1:8000/health`, `http://127.0.0.1:3000`, and `http://127.0.0.1:9090`.

## Trusted image workflow

Sheshnaag v2 uses trusted image profiles instead of ad hoc image names:

- `baseline`
- `osquery_capable`
- `tracee_capable`
- `secure_lima`

Build and verify the Docker-backed images with:

```bash
bash scripts/build_sheshnaag_osquery_image.sh
bash scripts/build_sheshnaag_tracee_image.sh
```

## Release verification

Use `.env.release.example` for rehearsals and run:

```bash
bash scripts/sheshnaag_release_rehearsal.sh
```

The default rehearsal emits environment metadata, image verification steps, Docker-backed smokes, and frontend/build checks.

For hosts that are expected to support secure-mode release gating, also run:

```bash
bash scripts/sheshnaag_secure_host_rehearsal.sh
```

That host lane archives:

- release metadata including `limactl` version
- the Alembic migration rehearsal summary
- Docker-backed advanced telemetry smoke logs
- secure-mode smoke JSON proving lifecycle, execute, and teardown audit metadata

## Secure-mode prerequisites

- `limactl` installed and working on the host
- writable `SHESHNAAG_LIMA_WORKSPACE_ROOT`
- access to the trusted `secure_lima` image/template path
- operators prepared to review bounded PCAP evidence before external export
