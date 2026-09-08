from collections.abc import Mapping
from typing import Protocol

from app.domain.payment import (
    CheckoutCallback,
    CreateSubscriptionInput,
    NormalizedPaymentEvent,
    PaymentCustomer,
    PaymentCustomerInput,
    ProviderSubscription,
)


class PaymentProvider(Protocol):
    """The core's business-language boundary for any payment gateway."""

    provider_name: str

    def validate_configuration(self) -> None: ...

    def create_customer(self, customer: PaymentCustomerInput) -> PaymentCustomer: ...

    def create_subscription(
        self, subscription: CreateSubscriptionInput
    ) -> ProviderSubscription: ...

    def checkout_payload(self, provider_subscription_id: str) -> dict[str, object]: ...

    def verify_checkout_signature(self, callback: CheckoutCallback) -> bool: ...

    def verify_webhook_signature(self, raw_body: bytes, signature_header: str) -> bool: ...

    def event_id_from_headers(self, headers: Mapping[str, str]) -> str | None: ...

    def signature_from_headers(self, headers: Mapping[str, str]) -> str | None: ...

    def parse_webhook_event(
        self, raw_body: bytes, provider_event_id: str
    ) -> NormalizedPaymentEvent: ...

    def cancel_subscription(
        self, provider_subscription_id: str, *, at_period_end: bool
    ) -> None: ...
