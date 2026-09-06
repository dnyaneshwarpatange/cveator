"""Serve newest-first pages without sorting the entire vulnerability payload table.

Revision ID: 20260906_03
Revises: 20260906_02
"""

import sqlalchemy as sa

from alembic import op

revision = "20260906_03"
down_revision = "20260906_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        valid = op.get_bind().scalar(sa.text(
            "SELECT indisvalid FROM pg_index "
            "WHERE indexrelid=to_regclass('ix_cves_newest_first')"
        ))
        if valid is False:
            op.execute("DROP INDEX CONCURRENTLY ix_cves_newest_first")
        op.execute("CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_cves_newest_first "
                   "ON cves (last_modified_at DESC NULLS LAST, id DESC)")


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_cves_newest_first")
