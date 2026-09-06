"""Durable product backfill requests and CVE browse indexes."""

import sqlalchemy as sa

from alembic import op

revision = "20260905_03"
down_revision = "20260905_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "product_syncs",
        sa.Column("product_id", sa.Integer(), sa.ForeignKey("products.id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("records", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_cves_last_modified", "cves", ["last_modified_at"])
    op.create_index("ix_cves_normalized", "cves", ["normalized_json"], postgresql_using="gin")


def downgrade() -> None:
    op.drop_index("ix_cves_normalized", "cves")
    op.drop_index("ix_cves_last_modified", "cves")
    op.drop_table("product_syncs")
