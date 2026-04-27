#!/usr/bin/env python3
"""Rehearse the Sheshnaag Alembic upgrade on a representative persisted baseline DB."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import sqlalchemy as sa

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.database import Base
import app.models  # noqa: F401
from app.models.sheshnaag import MaintainerAssessment


def create_baseline_db(path: Path) -> None:
    engine = sa.create_engine(f"sqlite:///{path}")
    metadata = sa.MetaData()

    sa.Table("tenants", metadata, sa.Column("id", sa.Integer, primary_key=True), sa.Column("slug", sa.String(120)))
    sa.Table("source_feeds", metadata, sa.Column("id", sa.Integer, primary_key=True), sa.Column("feed_key", sa.String(100)))
    sa.Table("cves", metadata, sa.Column("id", sa.Integer, primary_key=True), sa.Column("cve_id", sa.String(80)))
    sa.Table("package_records", metadata, sa.Column("id", sa.Integer, primary_key=True), sa.Column("name", sa.String(200)))
    sa.Table("product_records", metadata, sa.Column("id", sa.Integer, primary_key=True), sa.Column("name", sa.String(200)))
    sa.Table(
        "advisory_records",
        metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("source_feed_id", sa.Integer, sa.ForeignKey("source_feeds.id", ondelete="SET NULL")),
        sa.Column("cve_id", sa.Integer, sa.ForeignKey("cves.id", ondelete="CASCADE")),
        sa.Column("product_id", sa.Integer, sa.ForeignKey("product_records.id", ondelete="SET NULL")),
        sa.Column("external_id", sa.String(120)),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("summary", sa.Text),
        sa.Column("source_url", sa.Text),
        sa.Column("published_at", sa.DateTime),
        sa.Column("raw_data", sa.JSON),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
    )
    sa.Table(
        "version_ranges",
        metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("product_id", sa.Integer, sa.ForeignKey("product_records.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cve_id", sa.Integer, sa.ForeignKey("cves.id", ondelete="CASCADE")),
        sa.Column("version_start", sa.String(120)),
        sa.Column("version_end", sa.String(120)),
        sa.Column("fixed_version", sa.String(120)),
        sa.Column("is_inclusive_start", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("is_inclusive_end", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime),
    )

    metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(sa.text("INSERT INTO tenants (id, slug) VALUES (1, 'rehearsal-private')"))
        conn.execute(sa.text("INSERT INTO source_feeds (id, feed_key) VALUES (1, 'osv')"))
        conn.execute(sa.text("INSERT INTO cves (id, cve_id) VALUES (1, 'CVE-2099-0001')"))
        conn.execute(sa.text("INSERT INTO package_records (id, name) VALUES (1, 'acme-api-gateway')"))
        conn.execute(sa.text("INSERT INTO product_records (id, name) VALUES (1, 'acme-api-gateway')"))
        conn.execute(
            sa.text(
                "INSERT INTO advisory_records (id, source_feed_id, cve_id, product_id, external_id, title, summary) "
                "VALUES (1, 1, 1, 1, 'OSV-2099-1', 'Test advisory', 'baseline rehearsal row')"
            )
        )
        conn.execute(
            sa.text(
                "INSERT INTO version_ranges (id, product_id, cve_id, version_start, version_end, fixed_version, is_inclusive_start, is_inclusive_end) "
                "VALUES (1, 1, 1, '1.0.0', '1.0.9', '1.1.0', 1, 1)"
            )
        )


def run_alembic(db_url: str, command: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["DATABASE_URL"] = db_url
    return subprocess.run(
        [sys.executable, "-m", "alembic", *command],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def fetch_table_info(path: Path, table: str) -> list[dict[str, object]]:
    with sqlite3.connect(path) as conn:
        rows = conn.execute(f"PRAGMA table_info('{table}')").fetchall()
    return [{"cid": row[0], "name": row[1], "type": row[2], "notnull": row[3], "default": row[4], "pk": row[5]} for row in rows]


def table_exists(path: Path, table: str) -> bool:
    with sqlite3.connect(path) as conn:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
    return row is not None


def create_current_schema(path: Path) -> None:
    engine = sa.create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    engine.dispose()


def drop_maintainer_assessment_table(path: Path) -> None:
    engine = sa.create_engine(f"sqlite:///{path}")
    MaintainerAssessment.__table__.drop(engine, checkfirst=True)
    engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=None, help="Optional path to write the rehearsal summary JSON.")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="sheshnaag-migration-rehearsal-") as temp_dir:
        temp_root = Path(temp_dir)

        fresh_db_path = temp_root / "fresh-bootstrap.sqlite3"
        create_current_schema(fresh_db_path)
        fresh_maintainer_columns = fetch_table_info(fresh_db_path, "maintainer_assessments")

        v4_db_path = temp_root / "v4a04-rehearsal.sqlite3"
        v4_db_url = f"sqlite:///{v4_db_path}"
        create_current_schema(v4_db_path)
        drop_maintainer_assessment_table(v4_db_path)

        stamp = run_alembic(v4_db_url, ["stamp", "v4a03"])
        if stamp.returncode != 0:
            raise RuntimeError(f"Alembic stamp failed:\nSTDOUT:\n{stamp.stdout}\nSTDERR:\n{stamp.stderr}")

        upgrade = run_alembic(v4_db_url, ["upgrade", "head"])
        if upgrade.returncode != 0:
            raise RuntimeError(f"Alembic v4a04 upgrade failed:\nSTDOUT:\n{upgrade.stdout}\nSTDERR:\n{upgrade.stderr}")

        maintainer_columns = fetch_table_info(v4_db_path, "maintainer_assessments")

        downgrade = run_alembic(v4_db_url, ["downgrade", "v4a03"])
        if downgrade.returncode != 0:
            raise RuntimeError(f"Alembic v4a04 downgrade failed:\nSTDOUT:\n{downgrade.stdout}\nSTDERR:\n{downgrade.stderr}")

        maintainer_exists_after_downgrade = table_exists(v4_db_path, "maintainer_assessments")

        payload = {
            "fresh_bootstrap_database_url": f"sqlite:///{fresh_db_path}",
            "v4a04_rehearsal_database_url": v4_db_url,
            "stamp_stdout": stamp.stdout,
            "stamp_stderr": stamp.stderr,
            "upgrade_stdout": upgrade.stdout,
            "upgrade_stderr": upgrade.stderr,
            "downgrade_stdout": downgrade.stdout,
            "downgrade_stderr": downgrade.stderr,
            "validated_tables": {
                "fresh_bootstrap_maintainer_assessments": fresh_maintainer_columns,
                "v4a04_maintainer_assessments": maintainer_columns,
            },
            "checks": {
                "fresh_bootstrap_creates_maintainer_assessments": bool(fresh_maintainer_columns),
                "v4a03_to_v4a04_creates_maintainer_assessments": bool(maintainer_columns),
                "v4a04_downgrade_removes_maintainer_assessments": not maintainer_exists_after_downgrade,
                "maintainer_assessments_has_report_id": any(col["name"] == "report_id" for col in maintainer_columns),
            },
        }

        text = json.dumps(payload, indent=2, sort_keys=True)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text)
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
