"""phase 3 self-hosted auth and tenant roles

Revision ID: 20260904_03
Revises: 20260904_02
Create Date: 2026-09-04
"""

import sqlalchemy as sa

from alembic import op

revision = "20260904_03"
down_revision = "20260904_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=1024), nullable=False),
        sa.Column("role", sa.String(length=32), server_default="owner", nullable=False),
        sa.Column("token_version", sa.Integer(), server_default="0", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("role IN ('owner', 'admin', 'member', 'viewer')", name="ck_users_role"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_org_id", "users", ["org_id"])
    op.create_index("uq_users_email_lower", "users", [sa.text("lower(email)")], unique=True)


def downgrade() -> None:
    op.drop_index("uq_users_email_lower", table_name="users")
    op.drop_index("ix_users_org_id", table_name="users")
    op.drop_table("users")
