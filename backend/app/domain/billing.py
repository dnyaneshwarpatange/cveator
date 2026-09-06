from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class StoredCustomer:
    id: UUID
    org_id: UUID
    payment_provider: str
    provider_customer_id: str
    email: str


@dataclass(frozen=True, slots=True)
class StoredSubscription:
    id: UUID
    org_id: UUID
    payment_provider: str
    provider_subscription_id: str
    plan_id: str
    status: str
    current_period_end: datetime | None
    last_provider_event_at: datetime | None
    created_at: datetime
