"""Resumable full catalog import and searchable product families.

Revision ID: 20260905_02
Revises: 20260905_01
"""

import sqlalchemy as sa

from alembic import op

revision = "20260905_02"
down_revision = "20260905_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "products", sa.Column("is_family", sa.Boolean(), nullable=False, server_default="false")
    )
    op.execute(
        "CREATE INDEX ix_products_family_search_trgm ON products USING gin "
        "(lower(vendor || ' ' || product_name || ' ' || cpe_product) gin_trgm_ops) "
        "WHERE is_family = true"
    )
    op.create_table(
        "catalog_imports",
        sa.Column("source", sa.String(64), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("next_start_index", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_results", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("products_upserted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("error", sa.Text()),
    )


def downgrade() -> None:
    op.drop_table("catalog_imports")
    op.drop_index("ix_products_family_search_trgm", table_name="products")
    op.drop_column("products", "is_family")
