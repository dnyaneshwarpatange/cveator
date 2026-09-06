from typing import Protocol
from uuid import UUID

from app.domain.billing import StoredCustomer, StoredSubscription
from app.domain.payment import NormalizedPaymentEvent, PaymentCustomer, ProviderSubscription


class BillingRepository(Protocol):
    def get_customer(self, *, org_id: UUID, payment_provider: str) -> StoredCustomer | None: ...

    def save_customer(
        self,
        *,
        org_id: UUID,
        payment_provider: str,
        email: str,
        customer: PaymentCustomer,
    ) -> StoredCustomer: ...

    def create_subscription(
        self,
        *,
        org_id: UUID,
        payment_provider: str,
        plan_id: str,
        subscription: ProviderSubscription,
    ) -> StoredSubscription: ...

    def get_latest_subscription(self, *, org_id: UUID) -> StoredSubscription | None: ...

    def get_subscription(
        self, *, org_id: UUID, provider_subscription_id: str
    ) -> StoredSubscription | None: ...

    def claim_webhook_event(
        self, event: NormalizedPaymentEvent, *, payment_provider: str
    ) -> bool: ...

    def apply_payment_event(
        self, event: NormalizedPaymentEvent, *, payment_provider: str
    ) -> bool: ...

    def mark_webhook_processed(self, *, provider_event_id: str) -> None: ...
