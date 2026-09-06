from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from app.db.base import Base


class Organization(Base):
    """Tenant boundary for all organization-owned data."""

    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(1024), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="owner")
    token_version: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("role IN ('owner', 'admin', 'member', 'viewer')", name="ck_users_role"),
        Index("uq_users_email_lower", text("lower(email)"), unique=True),
        Index("ix_users_org_id", "org_id"),
    )


class Product(Base):
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(primary_key=True)
    part: Mapped[str] = mapped_column(String(1), nullable=False)
    vendor: Mapped[str] = mapped_column(String(255), nullable=False)
    product_name: Mapped[str] = mapped_column(String(512), nullable=False)
    cpe_product: Mapped[str] = mapped_column(String(255), nullable=False)
    cpe_version: Mapped[str] = mapped_column(String(255), nullable=False)
    cpe_string: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    is_family: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_products_cpe_identity", "part", "vendor", "cpe_product"),
        Index("ix_products_vendor_product", "vendor", "product_name"),
    )


class WatchlistItem(Base):
    __tablename__ = "watchlist_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id", ondelete="CASCADE"))
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("org_id", "product_id", name="uq_watchlist_items_org_product"),
        Index("ix_watchlist_items_product_org", "product_id", "org_id"),
    )


class CveProductMatch(Base):
    __tablename__ = "cve_product_matches"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id", ondelete="CASCADE"), nullable=False
    )
    matched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("cve_id", "product_id", name="uq_cve_product_matches_cve_product"),
        Index("ix_cve_product_matches_product_cve", "product_id", "cve_id"),
    )


class Alert(Base):
    """An organization-visible CVE match, separate from the global match graph."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="new", server_default="new"
    )
    plain_summary: Mapped[str | None] = mapped_column(Text)
    summary_provider: Mapped[str | None] = mapped_column(String(64))
    summary_generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("status IN ('new', 'read', 'dismissed')", name="ck_alerts_status"),
        UniqueConstraint("org_id", "cve_id", name="uq_alerts_org_cve"),
        Index("ix_alerts_org_status_created", "org_id", "status", "created_at"),
        Index(
            "ix_alerts_pending_delivery",
            "created_at",
            postgresql_where=text("sent_at IS NULL AND status = 'new'"),
        ),
    )
