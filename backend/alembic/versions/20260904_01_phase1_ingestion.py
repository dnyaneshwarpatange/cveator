"""phase 1 ingestion schema

Revision ID: 20260904_01
Revises:
Create Date: 2026-09-04
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260904_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cves",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("source_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("is_kev", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id"),
    )
    op.create_index("ix_cves_cve_id", "cves", ["cve_id"], unique=False)
    op.create_index("ix_cves_is_kev_cvss_score", "cves", ["is_kev", "cvss_score"], unique=False)
    op.create_table(
        "ingestion_cursors",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("high_watermark", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source", name="uq_ingestion_cursors_source"),
    )


def downgrade() -> None:
    op.drop_table("ingestion_cursors")
    op.drop_index("ix_cves_is_kev_cvss_score", table_name="cves")
    op.drop_index("ix_cves_cve_id", table_name="cves")
    op.drop_table("cves")
