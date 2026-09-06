from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.core.config import Settings
from app.domain.billing import StoredCustomer, StoredSubscription
from app.domain.payment import (
    NormalizedPaymentEvent,
    PaymentCustomer,
    PaymentEventType,
    ProviderSubscription,
)
from app.services.billing import BillingService
from app.services.billing_plans import BillingPlanCatalog


class FakeBillingRepository:
    def __init__(self) -> None:
        self.customer: StoredCustomer | None = None
        self.subscription: StoredSubscription | None = None
        self.claimed = True
        self.applied = False
        self.processed_event_id: str | None = None

    def get_customer(self, *, org_id: UUID, payment_provider: str) -> StoredCustomer | None:
        return self.customer

    def save_customer(
        self,
        *,
        org_id: UUID,
        payment_provider: str,
        email: str,
        customer: PaymentCustomer,
    ) -> StoredCustomer:
        self.customer = StoredCustomer(
            id=uuid4(),
            org_id=org_id,
            payment_provider=payment_provider,
            provider_customer_id=customer.provider_customer_id,
            email=email,
        )
        return self.customer

    def create_subscription(
        self,
        *,
        org_id: UUID,
        payment_provider: str,
        plan_id: str,
        subscription: ProviderSubscription,
    ) -> StoredSubscription:
        self.subscription = StoredSubscription(
            id=uuid4(),
            org_id=org_id,
            payment_provider=payment_provider,
            provider_subscription_id=subscription.provider_subscription_id,
            plan_id=plan_id,
            status=subscription.status,
            current_period_end=subscription.current_period_end,
            last_provider_event_at=None,
            created_at=datetime.now(UTC),
        )
        return self.subscription

    def get_latest_subscription(self, *, org_id: UUID) -> StoredSubscription | None:
        return self.subscription

    def get_subscription(
        self, *, org_id: UUID, provider_subscription_id: str
    ) -> StoredSubscription | None:
        if self.subscription and self.subscription.org_id == org_id:
            return self.subscription
        return None

    def claim_webhook_event(self, event: NormalizedPaymentEvent, *, payment_provider: str) -> bool:
        return self.claimed

    def apply_payment_event(self, event: NormalizedPaymentEvent, *, payment_provider: str) -> bool:
        self.applied = True
        return True

    def mark_webhook_processed(self, *, provider_event_id: str) -> None:
        self.processed_event_id = provider_event_id


class FakePaymentProvider:
    provider_name = "test-gateway"

    def __init__(self) -> None:
        self.cancelled = False

    def validate_configuration(self) -> None:
        return None

    def create_customer(self, customer) -> PaymentCustomer:
        return PaymentCustomer(provider_customer_id="customer-123")

    def create_subscription(self, subscription) -> ProviderSubscription:
        return ProviderSubscription(
            provider_subscription_id="subscription-123",
            status="created",
            current_period_end=None,
            checkout_payload={"provider": self.provider_name},
        )

    def verify_checkout_signature(self, callback) -> bool:
        return True

    def verify_webhook_signature(self, raw_body: bytes, signature_header: str) -> bool:
        return signature_header == "valid"

    def event_id_from_headers(self, headers):
        return None

    def signature_from_headers(self, headers):
        return None

    def parse_webhook_event(
        self, raw_body: bytes, provider_event_id: str
    ) -> NormalizedPaymentEvent:
        return _event(provider_event_id)

    def cancel_subscription(self, provider_subscription_id: str, *, at_period_end: bool) -> None:
        self.cancelled = True


def test_starts_checkout_with_an_internal_plan_and_persists_generic_identifiers() -> None:
    repository = FakeBillingRepository()
    provider = FakePaymentProvider()
    service = BillingService(repository, provider, _plans())
    org_id = uuid4()

    subscription, checkout_payload = service.start_checkout(
        org_id=org_id,
        organization_name="Acme IT",
        email="owner@example.com",
        plan_id="starter_monthly",
    )

    assert repository.customer is not None
    assert repository.customer.payment_provider == "test-gateway"
    assert subscription.provider_subscription_id == "subscription-123"
    assert checkout_payload == {"provider": "test-gateway"}


def test_webhook_duplicate_does_not_apply_a_second_state_change() -> None:
    repository = FakeBillingRepository()
    repository.claimed = False
    service = BillingService(repository, FakePaymentProvider(), _plans())

    assert not service.handle_webhook(
        raw_body=b"{}", signature="valid", provider_event_id="event-1"
    )
    assert not repository.applied
    assert repository.processed_event_id is None


def _plans() -> BillingPlanCatalog:
    return BillingPlanCatalog(
        Settings(
            billing_plans_json=(
                '{"starter_monthly":{"name":"Starter","description":"For small teams",'
                '"amount_paise":49900,"currency":"INR","interval":"monthly",'
                '"total_count":120}}'
            )
        )
    )


def _event(event_id: str) -> NormalizedPaymentEvent:
    return NormalizedPaymentEvent(
        provider_event_id=event_id,
        provider_event_type="subscription.charged",
        type=PaymentEventType.SUBSCRIPTION_CHARGED,
        org_id=uuid4(),
        provider_subscription_id="subscription-123",
        provider_payment_id="payment-123",
        amount_paise=49_900,
        currency="INR",
        current_period_end=None,
        occurred_at=datetime.now(UTC),
        payload={},
    )
