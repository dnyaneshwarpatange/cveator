import hashlib
import hmac
import json
from uuid import uuid4

from pydantic import SecretStr

from app.domain.payment import (
    BillingPlan,
    CheckoutCallback,
    CreateSubscriptionInput,
    PaymentCustomerInput,
    PaymentEventType,
)
from app.providers.razorpay.config import RazorpaySettings
from app.providers.razorpay.razorpay_payment_provider import RazorpayPaymentProvider


def test_creates_customer_and_subscription_with_gateway_metadata() -> None:
    org_id = uuid4()
    calls: list[tuple[str, str, dict[str, object]]] = []

    def request(method: str, path: str, payload: dict[str, object]) -> dict[str, object]:
        calls.append((method, path, payload))
        return {"id": "cust_test_123"} if path == "/v1/customers" else {"id": "sub_test_123"}

    provider = RazorpayPaymentProvider(_settings(), request=request)
    customer = provider.create_customer(
        PaymentCustomerInput(org_id=org_id, organization_name="Acme", email="owner@example.com")
    )
    subscription = provider.create_subscription(
        CreateSubscriptionInput(
            org_id=org_id,
            provider_customer_id=customer.provider_customer_id,
            plan=BillingPlan(
                id="starter_monthly",
                name="Starter",
                description="Test plan",
                amount_paise=49_900,
                currency="INR",
                interval="monthly",
                total_count=120,
            ),
        )
    )

    assert customer.provider_customer_id == "cust_test_123"
    assert subscription.provider_subscription_id == "sub_test_123"
    assert subscription.checkout_payload["provider"] == "razorpay"
    assert calls[0][1] == "/v1/customers"
    assert calls[0][2]["notes"] == {"org_id": str(org_id)}
    assert calls[1][1] == "/v1/subscriptions"
    assert calls[1][2]["plan_id"] == "plan_test_starter"
    assert "customer_id" not in calls[1][2]
    assert calls[1][2]["notes"] == {"org_id": str(org_id), "plan_id": "starter_monthly"}


def test_uses_subscription_checkout_signature_order_and_constant_time_comparison() -> None:
    provider = RazorpayPaymentProvider(_settings())
    message = b"pay_test_123|sub_test_123"
    signature = hmac.new(b"secret", message, hashlib.sha256).hexdigest()

    assert provider.verify_checkout_signature(
        CheckoutCallback(
            provider_subscription_id="sub_test_123",
            provider_payment_id="pay_test_123",
            signature=signature,
        )
    )
    assert not provider.verify_checkout_signature(
        CheckoutCallback(
            provider_subscription_id="sub_test_123",
            provider_payment_id="pay_test_123",
            signature="wrong",
        )
    )


def test_verifies_raw_webhook_bytes_and_normalizes_a_charged_event() -> None:
    org_id = uuid4()
    payload = {
        "entity": "event",
        "event": "subscription.charged",
        "created_at": 1_700_000_000,
        "payload": {
            "subscription": {
                "entity": {
                    "id": "sub_test_123",
                    "current_end": 1_700_100_000,
                    "notes": {"org_id": str(org_id)},
                }
            },
            "payment": {"entity": {"id": "pay_test_123", "amount": 49_900, "currency": "INR"}},
        },
    }
    raw_body = json.dumps(payload, separators=(",", ":")).encode()
    signature = hmac.new(b"webhook-secret", raw_body, hashlib.sha256).hexdigest()
    provider = RazorpayPaymentProvider(_settings())

    assert provider.verify_webhook_signature(raw_body, signature)
    assert not provider.verify_webhook_signature(raw_body + b" ", signature)
    event = provider.parse_webhook_event(raw_body, "event_test_123")

    assert event.provider_event_id == "event_test_123"
    assert event.type is PaymentEventType.SUBSCRIPTION_CHARGED
    assert event.org_id == org_id
    assert event.provider_subscription_id == "sub_test_123"
    assert event.provider_payment_id == "pay_test_123"
    assert event.amount_paise == 49_900
    assert (
        provider.event_id_from_headers({"X-Razorpay-Event-Id": "event_test_123"})
        == "event_test_123"
    )
    assert provider.signature_from_headers({"X-Razorpay-Signature": signature}) == signature


def _settings() -> RazorpaySettings:
    return RazorpaySettings(
        razorpay_key_id=SecretStr("key_test_123"),
        razorpay_key_secret=SecretStr("secret"),
        razorpay_webhook_secret=SecretStr("webhook-secret"),
        razorpay_plan_ids_json='{"starter_monthly":"plan_test_starter"}',
    )
