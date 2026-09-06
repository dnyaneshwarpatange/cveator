import hashlib
import hmac
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx

from app.domain.payment import (
    CheckoutCallback,
    CreateSubscriptionInput,
    NormalizedPaymentEvent,
    PaymentCustomer,
    PaymentCustomerInput,
    PaymentEventType,
    PaymentProviderError,
    PaymentProviderPayloadInvalid,
    ProviderSubscription,
)
from app.providers.razorpay.config import RazorpaySettings

ProviderRequest = Callable[[str, str, dict[str, object]], dict[str, object]]


class RazorpayPaymentProvider:
    """The sole gateway-specific adapter; it uses documented REST calls, not an SDK."""

    provider_name = "razorpay"

    def __init__(
        self,
        settings: RazorpaySettings,
        *,
        request: ProviderRequest | None = None,
    ) -> None:
        self._settings = settings
        self._request = request or self._send_request

    def validate_configuration(self) -> None:
        self._settings.require_api_credentials()
        self._settings.require_webhook_secret()

    def create_customer(self, customer: PaymentCustomerInput) -> PaymentCustomer:
        name = customer.organization_name.strip()
        if len(name) < 3:
            name = f"{name} Org"
        if len(customer.email) > 64:
            raise PaymentProviderPayloadInvalid("Customer email exceeds provider limits")
        payload = self._request(
            "POST",
            "/v1/customers",
            {
                "name": name[:50],
                "email": customer.email,
                "fail_existing": "0",
                "notes": {"org_id": str(customer.org_id)},
            },
        )
        return PaymentCustomer(provider_customer_id=_required_string(payload, "id"))

    def create_subscription(self, subscription: CreateSubscriptionInput) -> ProviderSubscription:
        provider_plan_id = self._settings.provider_plan_id(subscription.plan.id)
        payload = self._request(
            "POST",
            "/v1/subscriptions",
            {
                "plan_id": provider_plan_id,
                "total_count": subscription.plan.total_count,
                "quantity": 1,
                "customer_notify": False,
                "notes": {"org_id": str(subscription.org_id), "plan_id": subscription.plan.id},
            },
        )
        provider_subscription_id = _required_string(payload, "id")
        key_id, _ = self._settings.require_api_credentials()
        return ProviderSubscription(
            provider_subscription_id=provider_subscription_id,
            status=_subscription_status(payload.get("status")),
            current_period_end=_unix_timestamp(payload.get("current_end")),
            checkout_payload={
                "provider": self.provider_name,
                "script_url": self._settings.razorpay_checkout_script_url,
                "key_id": key_id,
                "provider_subscription_id": provider_subscription_id,
                "display_name": "CVE Monitor",
            },
        )

    def verify_checkout_signature(self, callback: CheckoutCallback) -> bool:
        _, key_secret = self._settings.require_api_credentials()
        message = f"{callback.provider_payment_id}|{callback.provider_subscription_id}".encode()
        expected_signature = hmac.new(key_secret.encode(), message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_signature, callback.signature)

    def verify_webhook_signature(self, raw_body: bytes, signature_header: str) -> bool:
        expected_signature = hmac.new(
            self._settings.require_webhook_secret().encode(), raw_body, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected_signature, signature_header)

    def event_id_from_headers(self, headers: Mapping[str, str]) -> str | None:
        for name, value in headers.items():
            if name.lower() == "x-razorpay-event-id" and value.strip():
                return value.strip()
        return None

    def signature_from_headers(self, headers: Mapping[str, str]) -> str | None:
        for name, value in headers.items():
            if name.lower() == "x-razorpay-signature" and value.strip():
                return value.strip()
        return None

    def parse_webhook_event(
        self, raw_body: bytes, provider_event_id: str
    ) -> NormalizedPaymentEvent:
        try:
            payload = json.loads(raw_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PaymentProviderPayloadInvalid("Webhook payload is not JSON") from error
        if not isinstance(payload, dict):
            raise PaymentProviderPayloadInvalid("Webhook payload is not an object")

        event_name = _required_string(payload, "event")
        subscription = _nested_entity(payload, "subscription")
        payment = _nested_entity(payload, "payment", required=False)
        provider_subscription_id = _optional_string(subscription, "id")
        org_id = _organization_id(subscription)
        return NormalizedPaymentEvent(
            provider_event_id=provider_event_id,
            provider_event_type=event_name,
            type=_event_type(event_name),
            org_id=org_id,
            provider_subscription_id=provider_subscription_id,
            provider_payment_id=_optional_string(payment, "id") if payment else None,
            amount_paise=_optional_int(payment, "amount") if payment else None,
            currency=_optional_string(payment, "currency") if payment else None,
            current_period_end=_unix_timestamp(subscription.get("current_end")),
            occurred_at=_unix_timestamp(payload.get("created_at")) or datetime.now(UTC),
            payload=payload,
        )

    def cancel_subscription(self, provider_subscription_id: str, *, at_period_end: bool) -> None:
        self._request(
            "POST",
            f"/v1/subscriptions/{provider_subscription_id}/cancel",
            {"cancel_at_cycle_end": at_period_end},
        )

    def _send_request(
        self, method: str, path: str, payload: dict[str, object]
    ) -> dict[str, object]:
        key_id, key_secret = self._settings.require_api_credentials()
        try:
            with httpx.Client(
                base_url=self._settings.razorpay_api_base_url.rstrip("/"), timeout=15.0
            ) as client:
                response = client.request(
                    method,
                    path,
                    auth=(key_id, key_secret),
                    json=payload,
                    headers={"content-type": "application/json"},
                )
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise PaymentProviderError("Payment provider request failed") from error
        if not isinstance(data, dict):
            raise PaymentProviderError("Payment provider returned an invalid response")
        return data


def _event_type(event_name: str) -> PaymentEventType | None:
    return {
        "subscription.activated": PaymentEventType.SUBSCRIPTION_ACTIVATED,
        "subscription.charged": PaymentEventType.SUBSCRIPTION_CHARGED,
        "subscription.cancelled": PaymentEventType.SUBSCRIPTION_CANCELLED,
        "subscription.pending": PaymentEventType.PAYMENT_FAILED,
        "subscription.halted": PaymentEventType.PAYMENT_FAILED,
    }.get(event_name)


def _nested_entity(
    payload: dict[str, object], name: str, *, required: bool = True
) -> dict[str, object] | None:
    container = payload.get("payload")
    nested = container.get(name) if isinstance(container, dict) else None
    entity = nested.get("entity") if isinstance(nested, dict) else None
    if isinstance(entity, dict):
        return entity
    if required:
        raise PaymentProviderPayloadInvalid(f"Webhook payload is missing {name} entity")
    return None


def _organization_id(subscription: dict[str, object] | None) -> UUID | None:
    if subscription is None:
        return None
    notes = subscription.get("notes")
    value = notes.get("org_id") if isinstance(notes, dict) else None
    if not isinstance(value, str):
        return None
    try:
        return UUID(value)
    except ValueError as error:
        raise PaymentProviderPayloadInvalid("Webhook organization note is invalid") from error


def _required_string(payload: dict[str, object], key: str) -> str:
    value = _optional_string(payload, key)
    if value is None:
        raise PaymentProviderPayloadInvalid(f"Payment provider response is missing {key}")
    return value


def _optional_string(payload: dict[str, object] | None, key: str) -> str | None:
    value = payload.get(key) if payload is not None else None
    return value.strip() if isinstance(value, str) and value.strip() else None


def _optional_int(payload: dict[str, object] | None, key: str) -> int | None:
    value = payload.get(key) if payload is not None else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _unix_timestamp(value: Any) -> datetime | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return datetime.fromtimestamp(value, tz=UTC)
    return None


def _subscription_status(value: object) -> str:
    return value if isinstance(value, str) and value else "created"
