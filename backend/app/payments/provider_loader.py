from importlib import import_module

from app.core.config import get_settings
from app.domain.payment import PaymentProviderUnavailable
from app.ports.payment_provider import PaymentProvider


def get_payment_provider() -> PaymentProvider:
    """Load the configured adapter without embedding a gateway in billing code."""
    provider_name = get_settings().payment_provider.strip().lower()
    if not provider_name:
        raise PaymentProviderUnavailable("No payment provider is configured")
    if not provider_name.replace("_", "").isalnum():
        raise PaymentProviderUnavailable("Configured payment provider has an invalid name")
    try:
        module = import_module(f"app.providers.{provider_name}.bootstrap")
        provider = module.create_payment_provider()
    except (ImportError, AttributeError) as error:
        raise PaymentProviderUnavailable("Configured payment provider is unavailable") from error
    if provider.provider_name != provider_name:
        raise PaymentProviderUnavailable("Configured payment provider identity is inconsistent")
    return provider
