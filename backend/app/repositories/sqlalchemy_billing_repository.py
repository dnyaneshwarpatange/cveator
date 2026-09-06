from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.domain.billing import StoredCustomer, StoredSubscription
from app.domain.payment import (
    NormalizedPaymentEvent,
    PaymentCustomer,
    PaymentEventType,
    ProviderSubscription,
)
from app.models.billing import Customer, Subscription, Transaction, WebhookEvent


class SqlAlchemyBillingRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_customer(self, *, org_id: UUID, payment_provider: str) -> StoredCustomer | None:
        customer = self._session.scalar(
            select(Customer).where(
                Customer.org_id == org_id,
                Customer.payment_provider == payment_provider,
            )
        )
        return _to_stored_customer(customer) if customer is not None else None

    def save_customer(
        self,
        *,
        org_id: UUID,
        payment_provider: str,
        email: str,
        customer: PaymentCustomer,
    ) -> StoredCustomer:
        statement = insert(Customer).values(
            org_id=org_id,
            payment_provider=payment_provider,
            provider_customer_id=customer.provider_customer_id,
            email=email,
        )
        statement = statement.on_conflict_do_nothing(constraint="uq_customers_org_provider")
        self._session.execute(statement)
        stored = self.get_customer(org_id=org_id, payment_provider=payment_provider)
        if stored is None:
            raise RuntimeError("Customer persistence did not return a record")
        return stored

    def create_subscription(
        self,
        *,
        org_id: UUID,
        payment_provider: str,
        plan_id: str,
        subscription: ProviderSubscription,
    ) -> StoredSubscription:
        statement = insert(Subscription).values(
            org_id=org_id,
            payment_provider=payment_provider,
            provider_subscription_id=subscription.provider_subscription_id,
            plan_id=plan_id,
            status=subscription.status,
            current_period_end=subscription.current_period_end,
        )
        statement = statement.on_conflict_do_nothing(
            constraint="uq_subscriptions_provider_subscription"
        )
        self._session.execute(statement)
        stored = self._session.scalar(
            select(Subscription).where(
                Subscription.payment_provider == payment_provider,
                Subscription.provider_subscription_id == subscription.provider_subscription_id,
            )
        )
        if stored is None or stored.org_id != org_id:
            raise RuntimeError("Subscription persistence did not return the organization record")
        return _to_stored_subscription(stored)

    def get_latest_subscription(self, *, org_id: UUID) -> StoredSubscription | None:
        subscription = self._session.scalar(
            select(Subscription)
            .where(Subscription.org_id == org_id)
            .order_by(Subscription.created_at.desc())
            .limit(1)
        )
        return _to_stored_subscription(subscription) if subscription is not None else None

    def get_subscription(
        self, *, org_id: UUID, provider_subscription_id: str
    ) -> StoredSubscription | None:
        subscription = self._session.scalar(
            select(Subscription).where(
                Subscription.org_id == org_id,
                Subscription.provider_subscription_id == provider_subscription_id,
            )
        )
        return _to_stored_subscription(subscription) if subscription is not None else None

    def claim_webhook_event(self, event: NormalizedPaymentEvent, *, payment_provider: str) -> bool:
        statement = insert(WebhookEvent).values(
            payment_provider=payment_provider,
            event_type=event.provider_event_type,
            provider_event_id=event.provider_event_id,
            payload=event.payload,
        )
        statement = statement.on_conflict_do_nothing(
            constraint="uq_webhook_events_provider_event_id"
        )
        result = self._session.execute(statement)
        return bool(result.rowcount)

    def apply_payment_event(self, event: NormalizedPaymentEvent, *, payment_provider: str) -> bool:
        if event.type is None or event.provider_subscription_id is None or event.org_id is None:
            return False
        subscription = self._session.scalar(
            select(Subscription).where(
                Subscription.payment_provider == payment_provider,
                Subscription.provider_subscription_id == event.provider_subscription_id,
            )
        )
        if subscription is None or subscription.org_id != event.org_id:
            return False

        is_newer = (
            subscription.last_provider_event_at is None
            or event.occurred_at >= subscription.last_provider_event_at
        )
        if is_newer:
            subscription.status = _subscription_status(event.type)
            if event.current_period_end is not None:
                subscription.current_period_end = event.current_period_end
            subscription.last_provider_event_at = event.occurred_at

        if event.provider_payment_id is not None:
            self._upsert_transaction(subscription, event, payment_provider)
        return True

    def mark_webhook_processed(self, *, provider_event_id: str) -> None:
        self._session.execute(
            update(WebhookEvent)
            .where(WebhookEvent.provider_event_id == provider_event_id)
            .values(processed_at=utc_now())
        )

    def _upsert_transaction(
        self,
        subscription: Subscription,
        event: NormalizedPaymentEvent,
        payment_provider: str,
    ) -> None:
        if event.provider_payment_id is None:
            return
        status = "failed" if event.type is PaymentEventType.PAYMENT_FAILED else "succeeded"
        statement = insert(Transaction).values(
            subscription_id=subscription.id,
            payment_provider=payment_provider,
            provider_payment_id=event.provider_payment_id,
            amount_paise=event.amount_paise or 0,
            currency=event.currency or "INR",
            status=status,
        )
        statement = statement.on_conflict_do_update(
            constraint="uq_transactions_provider_payment",
            set_={
                "amount_paise": event.amount_paise or 0,
                "currency": event.currency or "INR",
                "status": status,
            },
        )
        self._session.execute(statement)


def _subscription_status(event_type: PaymentEventType) -> str:
    if event_type in {
        PaymentEventType.SUBSCRIPTION_ACTIVATED,
        PaymentEventType.SUBSCRIPTION_CHARGED,
    }:
        return "active"
    if event_type is PaymentEventType.SUBSCRIPTION_CANCELLED:
        return "cancelled"
    return "past_due"


def _to_stored_customer(customer: Customer) -> StoredCustomer:
    return StoredCustomer(
        id=customer.id,
        org_id=customer.org_id,
        payment_provider=customer.payment_provider,
        provider_customer_id=customer.provider_customer_id,
        email=customer.email,
    )


def _to_stored_subscription(subscription: Subscription) -> StoredSubscription:
    return StoredSubscription(
        id=subscription.id,
        org_id=subscription.org_id,
        payment_provider=subscription.payment_provider,
        provider_subscription_id=subscription.provider_subscription_id,
        plan_id=subscription.plan_id,
        status=subscription.status,
        current_period_end=subscription.current_period_end,
        last_provider_event_at=subscription.last_provider_event_at,
        created_at=subscription.created_at,
    )
