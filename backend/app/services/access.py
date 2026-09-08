"""Server-owned application administration and fixed 72-hour monitoring trial."""

from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import exists, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.time import utc_now
from app.models.billing import Subscription
from app.models.catalog import Organization

TRIAL_DURATION = timedelta(days=3)


def is_application_admin(user_id: UUID) -> bool:
    return str(user_id) == get_settings().application_admin_user_id.strip()


def monitoring_access_condition(org_id, now: datetime | None = None):
    now = now or utc_now()
    trial = exists(
        select(Organization.id)
        .where(
            Organization.id == org_id,
            Organization.created_at > now - TRIAL_DURATION,
        )
        .correlate_except(Organization)
    )
    paid = exists(
        select(Subscription.id)
        .where(
            Subscription.org_id == org_id,
            Subscription.status == "active",
            Subscription.current_period_end > now,
            Subscription.last_provider_event_at.is_not(None),
        )
        .correlate_except(Subscription)
    )
    return or_(trial, paid)


def monitoring_access(session: Session, org_id: UUID) -> dict:
    now = utc_now()
    created = session.scalar(select(Organization.created_at).where(Organization.id == org_id))
    trial_end = created + TRIAL_DURATION if created else None
    paid_end = session.scalar(
        select(Subscription.current_period_end)
        .where(
            Subscription.org_id == org_id,
            Subscription.status == "active",
            Subscription.current_period_end > now,
            Subscription.last_provider_event_at.is_not(None),
        )
        .order_by(Subscription.current_period_end.desc())
        .limit(1)
    )
    trial_active = trial_end is not None and now < trial_end
    return {
        "has_access": bool(paid_end or trial_active),
        "status": "active" if paid_end else "trial" if trial_active else "expired",
        "trial_ends_at": trial_end,
        "current_period_end": paid_end,
    }
