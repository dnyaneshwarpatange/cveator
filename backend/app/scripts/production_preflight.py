"""Fail-fast configuration audit to run before a production deployment."""

import os
from dataclasses import dataclass
from urllib.parse import urlparse

from app.core.config import get_settings
from app.payments.provider_loader import get_payment_provider
from app.services.billing_plans import BillingPlanCatalog


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    passed: bool
    detail: str


def run_checks() -> list[Check]:
    settings = get_settings()
    checks: list[Check] = []

    checks.append(_call_check("runtime security", settings.validate_runtime_security))
    checks.append(
        Check(
            "production mode",
            settings.app_env.casefold() == "production",
            "APP_ENV must be production",
        )
    )
    checks.append(
        Check(
            "HTTPS public URL",
            urlparse(settings.public_app_url).scheme == "https",
            "PUBLIC_APP_URL must use https",
        )
    )
    checks.append(
        Check(
            "API documentation disabled",
            not settings.api_docs_enabled,
            "set API_DOCS_ENABLED=false",
        )
    )
    checks.append(
        Check(
            "explicit allowed hosts",
            bool(os.getenv("ALLOWED_HOSTS_CSV")) and "*" not in settings.allowed_hosts,
            "set ALLOWED_HOSTS_CSV to the public host and internal api hostname",
        )
    )
    checks.append(
        Check(
            "secure session cookie",
            os.getenv("SESSION_COOKIE_SECURE", "").casefold() == "true",
            "set SESSION_COOKIE_SECURE=true",
        )
    )
    checks.append(
        Check(
            "database credential",
            all(
                marker not in settings.database_url
                for marker in ("change-me", "local-development", "replace-")
            ),
            "replace example database credentials",
        )
    )
    placeholders = sorted(
        key for key, value in os.environ.items()
        if key in {"PUBLIC_APP_URL", "APP_ADDRESS", "POSTGRES_PASSWORD", "JWT_SECRET",
                   "EMAIL_FROM_ADDRESS", "MAIL_HOSTNAME", "MAIL_DOMAIN"}
        and ("replace-" in value or "example.com" in value)
    )
    checks.append(Check("deployment placeholders", not placeholders,
                        "replace example values: " + ", ".join(placeholders) if placeholders
                        else "no deployment placeholders"))
    checks.append(Check("internal health hosts", "127.0.0.1" in settings.allowed_hosts,
                        "ALLOWED_HOSTS_CSV must include 127.0.0.1 for container health checks"))
    checks.append(
        Check(
            "email delivery",
            settings.email_delivery_enabled,
            "complete SMTP/DNS setup and enable email delivery",
        )
    )
    checks.append(
        _call_check(
            "payment provider", lambda: get_payment_provider().validate_configuration()
        )
    )
    checks.append(
        _call_check("billing plans", lambda: _require_plans(BillingPlanCatalog(settings)))
    )
    return checks


def main() -> None:
    checks = run_checks()
    for check in checks:
        marker = "PASS" if check.passed else "FAIL"
        print(f"[{marker}] {check.name}: {check.detail}")
    if not all(check.passed for check in checks):
        raise SystemExit(1)


def _call_check(name: str, operation) -> Check:
    try:
        operation()
    except Exception as error:
        return Check(name, False, str(error))
    return Check(name, True, "configured")


def _require_plans(catalog: BillingPlanCatalog) -> None:
    if not catalog.list():
        raise RuntimeError("at least one billing plan is required")


if __name__ == "__main__":
    main()
