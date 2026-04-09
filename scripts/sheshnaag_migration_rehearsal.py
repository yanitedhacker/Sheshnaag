#!/usr/bin/env python3
"""Rehearse the Sheshnaag Alembic upgrade on a representative persisted baseline DB."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import tempfile
from pathlib import Path

import sqlalchemy as sa


ROOT = Path(__file__).resolve().parents[1]


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
        ["python", "-m", "alembic", *command],
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=None, help="Optional path to write the rehearsal summary JSON.")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="sheshnaag-migration-rehearsal-") as temp_dir:
        db_path = Path(temp_dir) / "rehearsal.sqlite3"
        db_url = f"sqlite:///{db_path}"
        create_baseline_db(db_path)

        upgrade = run_alembic(db_url, ["upgrade", "head"])
        if upgrade.returncode != 0:
            raise RuntimeError(f"Alembic upgrade failed:\nSTDOUT:\n{upgrade.stdout}\nSTDERR:\n{upgrade.stderr}")

        advisory_columns = fetch_table_info(db_path, "advisory_records")
        version_range_columns = fetch_table_info(db_path, "version_ranges")
        recalc_columns = fetch_table_info(db_path, "candidate_score_recalculation_runs")
        link_columns = fetch_table_info(db_path, "advisory_package_links")

        downgrade = run_alembic(db_url, ["downgrade", "base"])
        if downgrade.returncode != 0:
            raise RuntimeError(f"Alembic downgrade failed:\nSTDOUT:\n{downgrade.stdout}\nSTDERR:\n{downgrade.stderr}")

        payload = {
            "database_url": db_url,
            "upgrade_stdout": upgrade.stdout,
            "upgrade_stderr": upgrade.stderr,
            "downgrade_stdout": downgrade.stdout,
            "downgrade_stderr": downgrade.stderr,
            "validated_tables": {
                "advisory_records": advisory_columns,
                "version_ranges": version_range_columns,
                "candidate_score_recalculation_runs": recalc_columns,
                "advisory_package_links": link_columns,
            },
            "checks": {
                "advisory_records_has_canonical_id": any(col["name"] == "canonical_id" for col in advisory_columns),
                "version_ranges_has_normalized_bounds": any(col["name"] == "normalized_bounds" for col in version_range_columns),
                "recalc_runs_table_created": bool(recalc_columns),
                "advisory_package_links_table_created": bool(link_columns),
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
