"""phase 6 alert delivery queue index

Revision ID: 20260904_06
Revises: 20260904_05
Create Date: 2026-09-04
"""

import sqlalchemy as sa

from alembic import op

revision = "20260904_06"
down_revision = "20260904_05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_alerts_pending_delivery",
        "alerts",
        ["created_at"],
        unique=False,
        postgresql_where=sa.text("sent_at IS NULL AND status = 'new'"),
    )


def downgrade() -> None:
    op.drop_index("ix_alerts_pending_delivery", table_name="alerts")
