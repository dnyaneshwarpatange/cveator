"""phase 2 product catalog and matching schema

Revision ID: 20260904_02
Revises: 20260904_01
Create Date: 2026-09-04
"""

import sqlalchemy as sa

from alembic import op

revision = "20260904_02"
down_revision = "20260904_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "products",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("part", sa.String(length=1), nullable=False),
        sa.Column("vendor", sa.String(length=255), nullable=False),
        sa.Column("product_name", sa.String(length=512), nullable=False),
        sa.Column("cpe_product", sa.String(length=255), nullable=False),
        sa.Column("cpe_version", sa.String(length=255), nullable=False),
        sa.Column("cpe_string", sa.String(length=2048), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cpe_string"),
    )
    op.create_index("ix_products_cpe_identity", "products", ["part", "vendor", "cpe_product"])
    op.create_index("ix_products_vendor_product", "products", ["vendor", "product_name"])
    op.create_index(
        "ix_products_search_trgm",
        "products",
        ["product_name"],
        postgresql_using="gin",
        postgresql_ops={"product_name": "gin_trgm_ops"},
    )
    op.create_table(
        "watchlist_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("product_id", sa.Integer(), nullable=False),
        sa.Column(
            "added_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["product_id"], ["products.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "product_id", name="uq_watchlist_items_org_product"),
    )
    op.create_table(
        "cve_product_matches",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.Integer(), nullable=False),
        sa.Column("product_id", sa.Integer(), nullable=False),
        sa.Column(
            "matched_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["cve_id"], ["cves.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["product_id"], ["products.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id", "product_id", name="uq_cve_product_matches_cve_product"),
    )
    op.create_index(
        "ix_cve_product_matches_product_cve", "cve_product_matches", ["product_id", "cve_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_cve_product_matches_product_cve", table_name="cve_product_matches")
    op.drop_table("cve_product_matches")
    op.drop_table("watchlist_items")
    op.drop_index("ix_products_search_trgm", table_name="products")
    op.drop_index("ix_products_vendor_product", table_name="products")
    op.drop_index("ix_products_cpe_identity", table_name="products")
    op.drop_table("products")
    op.drop_table("organizations")
