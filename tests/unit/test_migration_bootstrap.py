"""Tests for fresh-database migration and container fail-closed startup."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


ROOT = Path(__file__).resolve().parents[2]


def _current_alembic_head() -> str:
    heads = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini"))).get_heads()
    assert len(heads) == 1
    return heads[0]


def test_current_schema_snapshot_can_adopt_v4_migration_history(tmp_path):
    output = tmp_path / "migration-rehearsal.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "sheshnaag_migration_rehearsal.py"),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["checks"] == {
        "fresh_bootstrap_creates_maintainer_assessments": True,
        "fresh_bootstrap_reaches_head": True,
        "maintainer_assessments_has_report_id": True,
        "v4a03_to_v4a04_creates_maintainer_assessments": True,
        "v4a04_downgrade_removes_maintainer_assessments": True,
    }


def test_current_schema_snapshot_installs_postgres_vector_extension_first():
    from app.migrations.bootstrap import create_current_schema_snapshot

    calls: list[tuple[str, object]] = []

    class FakeDialect:
        name = "postgresql"

    class FakeConnection:
        dialect = FakeDialect()

        def execute(self, statement):
            calls.append(("execute", str(statement)))

    class FakeMetadata:
        def create_all(self, *, bind):
            calls.append(("create_all", bind))

    connection = FakeConnection()
    create_current_schema_snapshot(connection, FakeMetadata())

    assert calls == [
        ("execute", "CREATE EXTENSION IF NOT EXISTS vector"),
        ("create_all", connection),
    ]


def test_alembic_upgrade_head_bootstraps_empty_database(tmp_path):
    expected_head = _current_alembic_head()
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
    assert revision == (expected_head,)
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
    assert f"{expected_head} (head)" in current.stdout


def test_alembic_console_script_can_import_application(tmp_path):
    expected_head = _current_alembic_head()
    database = tmp_path / "console-script.sqlite3"
    alembic_executable = Path(sys.executable).with_name("alembic")
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["DATABASE_URL"] = f"sqlite:///{database}"

    result = subprocess.run(
        [str(alembic_executable), "upgrade", "head"],
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
    assert revision == (expected_head,)


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
