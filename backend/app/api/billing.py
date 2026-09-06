from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_principal, require_roles
from app.core.config import get_settings
from app.db.session import get_session
from app.domain.auth import OrganizationRole, Principal
from app.domain.billing import StoredSubscription
from app.domain.payment import (
    BillingPlan,
    PaymentProviderError,
    PaymentProviderPayloadInvalid,
    PaymentProviderUnavailable,
    PaymentProviderVerificationFailed,
)
from app.models.catalog import Organization
from app.payments.provider_loader import get_payment_provider
from app.repositories.sqlalchemy_billing_repository import SqlAlchemyBillingRepository
from app.services.billing import BillingService
from app.services.billing_plans import BillingPlanCatalog

router = APIRouter(prefix="/billing", tags=["billing"])
_billing_managers = require_roles(OrganizationRole.OWNER, OrganizationRole.ADMIN)


class BillingPlanResponse(BaseModel):
    id: str
    name: str
    description: str
    amount_paise: int
    currency: str
    interval: str


class SubscriptionResponse(BaseModel):
    provider: str
    plan_id: str
    status: str
    current_period_end: datetime | None
    created_at: datetime


class CheckoutRequest(BaseModel):
    plan_id: str = Field(min_length=1, max_length=128)


class CheckoutResponse(BaseModel):
    subscription: SubscriptionResponse
    checkout_payload: dict[str, object]


class CheckoutVerificationRequest(BaseModel):
    provider_subscription_id: str = Field(min_length=1, max_length=255)
    provider_payment_id: str = Field(min_length=1, max_length=255)
    signature: str = Field(min_length=1, max_length=512)


class CancelSubscriptionRequest(BaseModel):
    at_period_end: bool = True


class CancelSubscriptionResponse(BaseModel):
    status: str
    message: str


@router.get("/plans", response_model=list[BillingPlanResponse])
def list_billing_plans(
    _: Annotated[Principal, Depends(get_current_principal)],
) -> list[BillingPlanResponse]:
    try:
        get_payment_provider().validate_configuration()
        plans = BillingPlanCatalog(get_settings()).list()
    except PaymentProviderUnavailable as error:
        raise _service_unavailable() from error
    return [_plan_response(plan) for plan in plans]


@router.get("/subscription", response_model=SubscriptionResponse | None)
def current_subscription(
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> SubscriptionResponse | None:
    subscription = SqlAlchemyBillingRepository(session).get_latest_subscription(
        org_id=principal.org_id
    )
    return _subscription_response(subscription) if subscription is not None else None


@router.post("/checkout", response_model=CheckoutResponse, status_code=status.HTTP_201_CREATED)
def start_checkout(
    payload: CheckoutRequest,
    principal: Annotated[Principal, Depends(_billing_managers)],
    session: Annotated[Session, Depends(get_session)],
) -> CheckoutResponse:
    organization_name = session.scalar(
        select(Organization.name).where(Organization.id == principal.org_id)
    )
    if organization_name is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Organization not found"
        )
    try:
        service = _billing_service(session)
        subscription, checkout_payload = service.start_checkout(
            org_id=principal.org_id,
            organization_name=organization_name,
            email=principal.email,
            plan_id=payload.plan_id,
        )
        session.commit()
    except PaymentProviderUnavailable as error:
        session.rollback()
        raise _service_unavailable() from error
    except PaymentProviderError as error:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Payment provider could not create a checkout session",
        ) from error
    except Exception:
        session.rollback()
        raise
    return CheckoutResponse(
        subscription=_subscription_response(subscription), checkout_payload=checkout_payload
    )


@router.post("/checkout/verify", status_code=status.HTTP_202_ACCEPTED)
def verify_checkout(
    payload: CheckoutVerificationRequest,
    principal: Annotated[Principal, Depends(_billing_managers)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, str]:
    try:
        _billing_service(session).verify_checkout(
            org_id=principal.org_id,
            provider_subscription_id=payload.provider_subscription_id,
            provider_payment_id=payload.provider_payment_id,
            signature=payload.signature,
        )
    except PaymentProviderUnavailable as error:
        raise _service_unavailable() from error
    except (PaymentProviderVerificationFailed, PaymentProviderPayloadInvalid) as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Checkout verification failed",
        ) from error
    return {"status": "verified_pending_webhook"}


@router.post("/subscription/cancel", response_model=CancelSubscriptionResponse)
def cancel_subscription(
    payload: CancelSubscriptionRequest,
    principal: Annotated[Principal, Depends(_billing_managers)],
    session: Annotated[Session, Depends(get_session)],
) -> CancelSubscriptionResponse:
    try:
        _billing_service(session).cancel_subscription(
            org_id=principal.org_id, at_period_end=payload.at_period_end
        )
    except PaymentProviderUnavailable as error:
        raise _service_unavailable() from error
    except PaymentProviderPayloadInvalid as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Subscription not found"
        ) from error
    except PaymentProviderError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Payment provider could not cancel the subscription",
        ) from error
    return CancelSubscriptionResponse(
        status="pending_webhook_confirmation",
        message="The cancellation request was sent. Billing status changes after confirmation.",
    )


@router.post("/webhooks/{provider_name}", status_code=status.HTTP_200_OK, include_in_schema=False)
async def payment_webhook(
    provider_name: str,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, str]:
    settings = get_settings()
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > settings.webhook_max_body_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail="Webhook payload is too large",
                )
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Webhook Content-Length is invalid",
            ) from None
    # This must be the first body access. Signature verification is over the exact bytes received.
    raw_body = await request.body()
    if len(raw_body) > settings.webhook_max_body_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Webhook payload is too large",
        )
    try:
        provider = get_payment_provider()
    except PaymentProviderUnavailable as error:
        raise _service_unavailable() from error
    if provider_name != provider.provider_name:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Webhook provider not found"
        )
    signature = provider.signature_from_headers(request.headers)
    event_id = provider.event_id_from_headers(request.headers)
    if signature is None or event_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Webhook headers are incomplete"
        )
    try:
        processed = BillingService(
            SqlAlchemyBillingRepository(session), provider, BillingPlanCatalog(get_settings())
        ).handle_webhook(
            raw_body=raw_body,
            signature=signature,
            provider_event_id=event_id,
        )
        session.commit()
    except PaymentProviderVerificationFailed as error:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Webhook signature is invalid"
        ) from error
    except PaymentProviderUnavailable as error:
        session.rollback()
        raise _service_unavailable() from error
    except PaymentProviderError as error:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Webhook payload is invalid"
        ) from error
    except Exception:
        session.rollback()
        raise
    return {"status": "processed" if processed else "duplicate"}


def _billing_service(session: Session) -> BillingService:
    return BillingService(
        SqlAlchemyBillingRepository(session),
        get_payment_provider(),
        BillingPlanCatalog(get_settings()),
    )


def _plan_response(plan: BillingPlan) -> BillingPlanResponse:
    return BillingPlanResponse(
        id=plan.id,
        name=plan.name,
        description=plan.description,
        amount_paise=plan.amount_paise,
        currency=plan.currency,
        interval=plan.interval,
    )


def _subscription_response(subscription: StoredSubscription) -> SubscriptionResponse:
    return SubscriptionResponse(
        provider=subscription.payment_provider,
        plan_id=subscription.plan_id,
        status=subscription.status,
        current_period_end=subscription.current_period_end,
        created_at=subscription.created_at,
    )


def _service_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Billing is not configured",
    )
