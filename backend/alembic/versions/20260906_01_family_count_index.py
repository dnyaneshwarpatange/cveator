"""Keep live catalog counts off the full version dictionary heap.

Revision ID: 20260906_01
Revises: 20260905_03
"""

import sqlalchemy as sa

from alembic import op

revision = "20260906_01"
down_revision = "20260905_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        valid = op.get_bind().scalar(sa.text(
            "SELECT indisvalid FROM pg_index "
            "WHERE indexrelid=to_regclass('ix_products_family_count')"
        ))
        if valid is False:
            op.execute("DROP INDEX CONCURRENTLY ix_products_family_count")
        op.execute("CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_products_family_count "
                   "ON products (id) WHERE is_family IS TRUE")


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_products_family_count")
