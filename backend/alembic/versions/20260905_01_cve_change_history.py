"""Source-aware CVE projection and append-only meaningful change history.

Revision ID: 20260905_01
Revises: 20260904_06
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260905_01"
down_revision = "20260904_06"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "cves",
        sa.Column("normalized_json", postgresql.JSONB(), nullable=False, server_default="{}"),
    )
    op.create_table(
        "cve_changes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "cve_id", sa.Integer(), sa.ForeignKey("cves.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("changes", postgresql.JSONB(), nullable=False),
        sa.Column("source_modified_at", sa.DateTime(timezone=True)),
        sa.Column(
            "observed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_cve_changes_cve_observed", "cve_changes", ["cve_id", "observed_at"])


def downgrade() -> None:
    op.drop_table("cve_changes")
    op.drop_column("cves", "normalized_json")
