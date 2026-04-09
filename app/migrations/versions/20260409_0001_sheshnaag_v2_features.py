"""Sheshnaag v2 advisory normalization and secure-mode schema additions."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260409_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("advisory_records") as batch_op:
        batch_op.add_column(sa.Column("package_record_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("canonical_id", sa.String(length=160), nullable=True))
        batch_op.add_column(sa.Column("advisory_type", sa.String(length=80), nullable=True))
        batch_op.add_column(sa.Column("severity", sa.String(length=40), nullable=True))
        batch_op.add_column(sa.Column("normalization_confidence", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("aliases", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("references", sa.JSON(), nullable=True))
        batch_op.create_foreign_key("fk_advisory_records_package_record_id", "package_records", ["package_record_id"], ["id"], ondelete="SET NULL")
        batch_op.create_index("ix_advisory_records_package_record_id", ["package_record_id"], unique=False)
        batch_op.create_index("ix_advisory_records_canonical_id", ["canonical_id"], unique=False)
        batch_op.create_index("ix_advisory_records_advisory_type", ["advisory_type"], unique=False)
        batch_op.create_index("ix_advisory_records_severity", ["severity"], unique=False)

    op.create_table(
        "advisory_package_links",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("advisory_record_id", sa.Integer(), nullable=False),
        sa.Column("package_record_id", sa.Integer(), nullable=False),
        sa.Column("package_role", sa.String(length=80), nullable=True),
        sa.Column("purl", sa.String(length=500), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["advisory_record_id"], ["advisory_records.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["package_record_id"], ["package_records.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("advisory_record_id", "package_record_id", name="uq_advisory_package_link"),
    )
    op.create_index(op.f("ix_advisory_package_links_id"), "advisory_package_links", ["id"], unique=False)
    op.create_index(op.f("ix_advisory_package_links_advisory_record_id"), "advisory_package_links", ["advisory_record_id"], unique=False)
    op.create_index(op.f("ix_advisory_package_links_package_record_id"), "advisory_package_links", ["package_record_id"], unique=False)

    op.create_table(
        "candidate_score_recalculation_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("dry_run", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("filters", sa.JSON(), nullable=True),
        sa.Column("summary", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_candidate_score_recalculation_runs_id"),
        "candidate_score_recalculation_runs",
        ["id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_candidate_score_recalculation_runs_tenant_id"),
        "candidate_score_recalculation_runs",
        ["tenant_id"],
        unique=False,
    )

    with op.batch_alter_table("version_ranges") as batch_op:
        batch_op.add_column(sa.Column("advisory_record_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("package_record_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("range_type", sa.String(length=80), nullable=True))
        batch_op.add_column(sa.Column("source_label", sa.String(length=120), nullable=True))
        batch_op.add_column(sa.Column("normalized_bounds", sa.JSON(), nullable=True))
        batch_op.alter_column("product_id", existing_type=sa.Integer(), nullable=True)
        batch_op.create_foreign_key("fk_version_ranges_advisory_record_id", "advisory_records", ["advisory_record_id"], ["id"], ondelete="CASCADE")
        batch_op.create_foreign_key("fk_version_ranges_package_record_id", "package_records", ["package_record_id"], ["id"], ondelete="SET NULL")
        batch_op.create_index("ix_version_ranges_advisory_record_id", ["advisory_record_id"], unique=False)
        batch_op.create_index("ix_version_ranges_package_record_id", ["package_record_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("version_ranges") as batch_op:
        batch_op.drop_index("ix_version_ranges_package_record_id")
        batch_op.drop_index("ix_version_ranges_advisory_record_id")
        batch_op.drop_constraint("fk_version_ranges_package_record_id", type_="foreignkey")
        batch_op.drop_constraint("fk_version_ranges_advisory_record_id", type_="foreignkey")
        batch_op.alter_column("product_id", existing_type=sa.Integer(), nullable=False)
        batch_op.drop_column("normalized_bounds")
        batch_op.drop_column("source_label")
        batch_op.drop_column("range_type")
        batch_op.drop_column("package_record_id")
        batch_op.drop_column("advisory_record_id")

    op.drop_index(op.f("ix_advisory_package_links_package_record_id"), table_name="advisory_package_links")
    op.drop_index(op.f("ix_advisory_package_links_advisory_record_id"), table_name="advisory_package_links")
    op.drop_index(op.f("ix_advisory_package_links_id"), table_name="advisory_package_links")
    op.drop_table("advisory_package_links")
    op.drop_index(op.f("ix_candidate_score_recalculation_runs_tenant_id"), table_name="candidate_score_recalculation_runs")
    op.drop_index(op.f("ix_candidate_score_recalculation_runs_id"), table_name="candidate_score_recalculation_runs")
    op.drop_table("candidate_score_recalculation_runs")

    with op.batch_alter_table("advisory_records") as batch_op:
        batch_op.drop_index("ix_advisory_records_severity")
        batch_op.drop_index("ix_advisory_records_advisory_type")
        batch_op.drop_index("ix_advisory_records_canonical_id")
        batch_op.drop_index("ix_advisory_records_package_record_id")
        batch_op.drop_constraint("fk_advisory_records_package_record_id", type_="foreignkey")
        batch_op.drop_column("references")
        batch_op.drop_column("aliases")
        batch_op.drop_column("normalization_confidence")
        batch_op.drop_column("severity")
        batch_op.drop_column("advisory_type")
        batch_op.drop_column("canonical_id")
        batch_op.drop_column("package_record_id")
