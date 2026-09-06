from app.domain.billing import StoredSubscription
from app.domain.payment import (
    CheckoutCallback,
    CreateSubscriptionInput,
    NormalizedPaymentEvent,
    PaymentCustomerInput,
    PaymentProviderPayloadInvalid,
    PaymentProviderVerificationFailed,
)
from app.ports.billing_repository import BillingRepository
from app.ports.payment_provider import PaymentProvider
from app.services.billing_plans import BillingPlanCatalog


class BillingService:
    def __init__(
        self,
        repository: BillingRepository,
        provider: PaymentProvider,
        plans: BillingPlanCatalog,
    ) -> None:
        self._repository = repository
        self._provider = provider
        self._plans = plans

    def start_checkout(
        self, *, org_id, organization_name: str, email: str, plan_id: str
    ) -> tuple[StoredSubscription, dict[str, object]]:
        plan = self._plans.get(plan_id)
        customer = self._repository.get_customer(
            org_id=org_id, payment_provider=self._provider.provider_name
        )
        if customer is None:
            created_customer = self._provider.create_customer(
                PaymentCustomerInput(
                    org_id=org_id,
                    organization_name=organization_name,
                    email=email,
                )
            )
            customer = self._repository.save_customer(
                org_id=org_id,
                payment_provider=self._provider.provider_name,
                email=email,
                customer=created_customer,
            )
        provider_subscription = self._provider.create_subscription(
            subscription=CreateSubscriptionInput(
                org_id=org_id,
                provider_customer_id=customer.provider_customer_id,
                plan=plan,
            )
        )
        subscription = self._repository.create_subscription(
            org_id=org_id,
            payment_provider=self._provider.provider_name,
            plan_id=plan.id,
            subscription=provider_subscription,
        )
        return subscription, provider_subscription.checkout_payload

    def verify_checkout(
        self,
        *,
        org_id,
        provider_subscription_id: str,
        provider_payment_id: str,
        signature: str,
    ) -> None:
        subscription = self._repository.get_subscription(
            org_id=org_id, provider_subscription_id=provider_subscription_id
        )
        if subscription is None or subscription.payment_provider != self._provider.provider_name:
            raise PaymentProviderPayloadInvalid("Subscription does not belong to this organization")
        if not self._provider.verify_checkout_signature(
            CheckoutCallback(
                provider_subscription_id=provider_subscription_id,
                provider_payment_id=provider_payment_id,
                signature=signature,
            )
        ):
            raise PaymentProviderVerificationFailed("Checkout signature is invalid")

    def cancel_subscription(self, *, org_id, at_period_end: bool) -> StoredSubscription:
        subscription = self._repository.get_latest_subscription(org_id=org_id)
        if subscription is None or subscription.payment_provider != self._provider.provider_name:
            raise PaymentProviderPayloadInvalid("No subscription is available to cancel")
        self._provider.cancel_subscription(
            subscription.provider_subscription_id, at_period_end=at_period_end
        )
        # The webhook remains the payment-state authority; do not mark this cancelled here.
        return subscription

    def handle_webhook(
        self,
        *,
        raw_body: bytes,
        signature: str,
        provider_event_id: str,
    ) -> bool:
        if not self._provider.verify_webhook_signature(raw_body, signature):
            raise PaymentProviderVerificationFailed("Webhook signature is invalid")
        event: NormalizedPaymentEvent = self._provider.parse_webhook_event(
            raw_body, provider_event_id
        )
        claimed = self._repository.claim_webhook_event(
            event, payment_provider=self._provider.provider_name
        )
        if not claimed:
            return False
        self._repository.apply_payment_event(event, payment_provider=self._provider.provider_name)
        self._repository.mark_webhook_processed(provider_event_id=event.provider_event_id)
        return True
