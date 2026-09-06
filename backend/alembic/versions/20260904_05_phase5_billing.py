"""phase 5 provider-neutral billing

Revision ID: 20260904_05
Revises: 20260904_04
Create Date: 2026-09-04
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260904_05"
down_revision = "20260904_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "customers",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("payment_provider", sa.String(length=64), nullable=False),
        sa.Column("provider_customer_id", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "payment_provider", name="uq_customers_org_provider"),
        sa.UniqueConstraint(
            "payment_provider", "provider_customer_id", name="uq_customers_provider_customer"
        ),
    )
    op.create_table(
        "subscriptions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("payment_provider", sa.String(length=64), nullable=False),
        sa.Column("provider_subscription_id", sa.String(length=255), nullable=False),
        sa.Column("plan_id", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_provider_event_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "payment_provider",
            "provider_subscription_id",
            name="uq_subscriptions_provider_subscription",
        ),
    )
    op.create_index("ix_subscriptions_org_created", "subscriptions", ["org_id", "created_at"])
    op.create_table(
        "transactions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("subscription_id", sa.Uuid(), nullable=False),
        sa.Column("payment_provider", sa.String(length=64), nullable=False),
        sa.Column("provider_payment_id", sa.String(length=255), nullable=False),
        sa.Column("amount_paise", sa.Integer(), nullable=False),
        sa.Column("currency", sa.String(length=8), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("amount_paise >= 0", name="ck_transactions_amount_nonnegative"),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscriptions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "payment_provider", "provider_payment_id", name="uq_transactions_provider_payment"
        ),
    )
    op.create_table(
        "webhook_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("payment_provider", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("provider_event_id", sa.String(length=255), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider_event_id", name="uq_webhook_events_provider_event_id"),
    )


def downgrade() -> None:
    op.drop_table("webhook_events")
    op.drop_table("transactions")
    op.drop_index("ix_subscriptions_org_created", table_name="subscriptions")
    op.drop_table("subscriptions")
    op.drop_table("customers")
