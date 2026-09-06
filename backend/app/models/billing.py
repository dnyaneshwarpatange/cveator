from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from app.db.base import Base


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    payment_provider: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_customer_id: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("org_id", "payment_provider", name="uq_customers_org_provider"),
        UniqueConstraint(
            "payment_provider", "provider_customer_id", name="uq_customers_provider_customer"
        ),
    )


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    payment_provider: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_subscription_id: Mapped[str] = mapped_column(String(255), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_provider_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "payment_provider",
            "provider_subscription_id",
            name="uq_subscriptions_provider_subscription",
        ),
        Index("ix_subscriptions_org_created", "org_id", "created_at"),
    )


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    subscription_id: Mapped[UUID] = mapped_column(
        ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False
    )
    payment_provider: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_payment_id: Mapped[str] = mapped_column(String(255), nullable=False)
    amount_paise: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(8), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("amount_paise >= 0", name="ck_transactions_amount_nonnegative"),
        UniqueConstraint(
            "payment_provider", "provider_payment_id", name="uq_transactions_provider_payment"
        ),
    )


class WebhookEvent(Base):
    __tablename__ = "webhook_events"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    payment_provider: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_event_id: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("provider_event_id", name="uq_webhook_events_provider_event_id"),
    )
