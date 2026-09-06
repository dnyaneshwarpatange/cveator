from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class PaymentEventType(StrEnum):
    SUBSCRIPTION_ACTIVATED = "subscription.activated"
    SUBSCRIPTION_CHARGED = "subscription.charged"
    SUBSCRIPTION_CANCELLED = "subscription.cancelled"
    PAYMENT_FAILED = "payment.failed"


@dataclass(frozen=True, slots=True)
class BillingPlan:
    id: str
    name: str
    description: str
    amount_paise: int
    currency: str
    interval: str
    total_count: int


@dataclass(frozen=True, slots=True)
class PaymentCustomerInput:
    org_id: UUID
    organization_name: str
    email: str


@dataclass(frozen=True, slots=True)
class PaymentCustomer:
    provider_customer_id: str


@dataclass(frozen=True, slots=True)
class CreateSubscriptionInput:
    org_id: UUID
    provider_customer_id: str
    plan: BillingPlan


@dataclass(frozen=True, slots=True)
class ProviderSubscription:
    provider_subscription_id: str
    status: str
    current_period_end: datetime | None
    checkout_payload: dict[str, object]


@dataclass(frozen=True, slots=True)
class CheckoutCallback:
    provider_subscription_id: str
    provider_payment_id: str
    signature: str


@dataclass(frozen=True, slots=True)
class NormalizedPaymentEvent:
    provider_event_id: str
    provider_event_type: str
    type: PaymentEventType | None
    org_id: UUID | None
    provider_subscription_id: str | None
    provider_payment_id: str | None
    amount_paise: int | None
    currency: str | None
    current_period_end: datetime | None
    occurred_at: datetime
    payload: dict[str, object]


class PaymentProviderError(Exception):
    """An expected integration or configuration failure that is safe to report generically."""


class PaymentProviderUnavailable(PaymentProviderError):
    pass


class PaymentProviderVerificationFailed(PaymentProviderError):
    pass


class PaymentProviderPayloadInvalid(PaymentProviderError):
    pass
