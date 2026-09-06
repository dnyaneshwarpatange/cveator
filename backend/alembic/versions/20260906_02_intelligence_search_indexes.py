"""Index description and affected-identity substring searches.

Revision ID: 20260906_02
Revises: 20260906_01
"""

import sqlalchemy as sa

from alembic import op

revision = "20260906_02"
down_revision = "20260906_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        for field in ("description", "products"):
            name = f"ix_cves_{field}_trgm"
            valid = op.get_bind().scalar(sa.text(
                "SELECT indisvalid FROM pg_index WHERE indexrelid=to_regclass(:name)"
            ), {"name": name})
            if valid is False:
                op.execute(f"DROP INDEX CONCURRENTLY {name}")
            op.execute(f"CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_cves_{field}_trgm "
                       f"ON cves USING gin ((normalized_json ->> '{field}') gin_trgm_ops)")


def downgrade() -> None:
    with op.get_context().autocommit_block():
        for field in ("description", "products"):
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS ix_cves_{field}_trgm")
