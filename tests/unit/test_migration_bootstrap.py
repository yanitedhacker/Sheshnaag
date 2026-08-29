"""Tests for fresh-database migration and container fail-closed startup."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_alembic_upgrade_head_bootstraps_empty_database(tmp_path):
    database = tmp_path / "fresh.sqlite3"
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{database}"

    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    with sqlite3.connect(database) as connection:
        revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        agent_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info('autonomous_agent_runs')")
        }
    assert revision == ("v5a08",)
    assert {
        "tenants",
        "advisory_records",
        "authorization_request_records",
        "autonomous_agent_runs",
    }.issubset(tables)
    assert {
        "disposition",
        "action_digest",
        "authorization_artifact_id",
    }.issubset(agent_columns)

    repeated = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    current = subprocess.run(
        [sys.executable, "-m", "alembic", "current", "--check-heads"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert repeated.returncode == 0, repeated.stderr
    assert current.returncode == 0, current.stderr
    assert "v5a08 (head)" in current.stdout


def test_container_entrypoint_does_not_start_api_after_migration_failure(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "uvicorn-started"
    alembic = fake_bin / "alembic"
    uvicorn = fake_bin / "uvicorn"
    alembic.write_text("#!/bin/sh\nexit 23\n", encoding="utf-8")
    uvicorn.write_text(
        "#!/bin/sh\ntouch \"$SHESHNAAG_TEST_UVICORN_MARKER\"\n",
        encoding="utf-8",
    )
    alembic.chmod(0o755)
    uvicorn.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:/usr/bin:/bin"
    env["SHESHNAAG_TEST_UVICORN_MARKER"] = str(marker)

    result = subprocess.run(
        ["/bin/bash", str(ROOT / "docker-entrypoint.sh")],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 23
    assert not marker.exists()
