"""phase 4 dashboard alerts

Revision ID: 20260904_04
Revises: 20260904_03
Create Date: 2026-09-04
"""

import sqlalchemy as sa

from alembic import op

revision = "20260904_04"
down_revision = "20260904_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("cve_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="new", nullable=False),
        sa.Column("plain_summary", sa.Text(), nullable=True),
        sa.Column("summary_provider", sa.String(length=64), nullable=True),
        sa.Column("summary_generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("status IN ('new', 'read', 'dismissed')", name="ck_alerts_status"),
        sa.ForeignKeyConstraint(["cve_id"], ["cves.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "cve_id", name="uq_alerts_org_cve"),
    )
    op.create_index("ix_alerts_org_status_created", "alerts", ["org_id", "status", "created_at"])
    op.create_index("ix_watchlist_items_product_org", "watchlist_items", ["product_id", "org_id"])


def downgrade() -> None:
    op.drop_index("ix_watchlist_items_product_org", table_name="watchlist_items")
    op.drop_index("ix_alerts_org_status_created", table_name="alerts")
    op.drop_table("alerts")
