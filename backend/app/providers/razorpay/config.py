import json

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.domain.payment import PaymentProviderUnavailable


class RazorpaySettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    razorpay_key_id: SecretStr | None = None
    razorpay_key_secret: SecretStr | None = None
    razorpay_webhook_secret: SecretStr | None = None
    razorpay_plan_ids_json: str = "{}"
    razorpay_api_base_url: str = "https://api.razorpay.com"
    razorpay_checkout_script_url: str = "https://checkout.razorpay.com/v1/checkout.js"

    def require_api_credentials(self) -> tuple[str, str]:
        key_id = self.razorpay_key_id.get_secret_value() if self.razorpay_key_id else ""
        key_secret = self.razorpay_key_secret.get_secret_value() if self.razorpay_key_secret else ""
        if not key_id or not key_secret or "replace" in key_id or "replace" in key_secret:
            raise PaymentProviderUnavailable("Payment provider API credentials are not configured")
        return key_id, key_secret

    def require_webhook_secret(self) -> str:
        secret = (
            self.razorpay_webhook_secret.get_secret_value() if self.razorpay_webhook_secret else ""
        )
        if not secret or "replace" in secret:
            raise PaymentProviderUnavailable("Payment provider webhook secret is not configured")
        return secret

    def provider_plan_id(self, internal_plan_id: str) -> str:
        try:
            plan_ids = json.loads(self.razorpay_plan_ids_json)
        except json.JSONDecodeError as error:
            raise PaymentProviderUnavailable("Provider plan mapping is not valid JSON") from error
        provider_plan_id = plan_ids.get(internal_plan_id) if isinstance(plan_ids, dict) else None
        if not isinstance(provider_plan_id, str) or not provider_plan_id.strip():
            raise PaymentProviderUnavailable("Provider plan mapping is missing the selected plan")
        return provider_plan_id.strip()
