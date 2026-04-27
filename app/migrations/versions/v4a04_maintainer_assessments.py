"""V4 OSS maintainer assessment records.

Revision ID: v4a04
Revises: v4a03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "v4a04"
down_revision = "v4a03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "maintainer_assessments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("repository_url", sa.Text(), nullable=False),
        sa.Column("repository_name", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="completed"),
        sa.Column("summary", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("source_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("sbom_sha256", sa.String(length=64), nullable=False),
        sa.Column("vex_sha256", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("analysis_case_id", sa.Integer(), nullable=True),
        sa.Column("report_id", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["analysis_case_id"], ["analysis_cases.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["report_id"], ["malware_reports.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "repository_url",
            "sbom_sha256",
            "vex_sha256",
            name="uq_maintainer_assessment_input",
        ),
    )
    op.create_index(op.f("ix_maintainer_assessments_id"), "maintainer_assessments", ["id"], unique=False)
    op.create_index(
        "ix_maintainer_assessments_tenant_repo",
        "maintainer_assessments",
        ["tenant_id", "repository_url"],
        unique=False,
    )
    op.create_index(
        op.f("ix_maintainer_assessments_tenant_id"),
        "maintainer_assessments",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_maintainer_assessments_status"),
        "maintainer_assessments",
        ["status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_maintainer_assessments_sbom_sha256"),
        "maintainer_assessments",
        ["sbom_sha256"],
        unique=False,
    )
    op.create_index(
        op.f("ix_maintainer_assessments_vex_sha256"),
        "maintainer_assessments",
        ["vex_sha256"],
        unique=False,
    )
    op.create_index(
        op.f("ix_maintainer_assessments_analysis_case_id"),
        "maintainer_assessments",
        ["analysis_case_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_maintainer_assessments_report_id"),
        "maintainer_assessments",
        ["report_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_maintainer_assessments_report_id"), table_name="maintainer_assessments")
    op.drop_index(op.f("ix_maintainer_assessments_analysis_case_id"), table_name="maintainer_assessments")
    op.drop_index(op.f("ix_maintainer_assessments_vex_sha256"), table_name="maintainer_assessments")
    op.drop_index(op.f("ix_maintainer_assessments_sbom_sha256"), table_name="maintainer_assessments")
    op.drop_index(op.f("ix_maintainer_assessments_status"), table_name="maintainer_assessments")
    op.drop_index(op.f("ix_maintainer_assessments_tenant_id"), table_name="maintainer_assessments")
    op.drop_index("ix_maintainer_assessments_tenant_repo", table_name="maintainer_assessments")
    op.drop_index(op.f("ix_maintainer_assessments_id"), table_name="maintainer_assessments")
    op.drop_table("maintainer_assessments")
