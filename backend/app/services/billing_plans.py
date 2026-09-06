import json

from app.core.config import Settings
from app.domain.payment import BillingPlan, PaymentProviderUnavailable


class BillingPlanCatalog:
    """Configuration-backed plans with internal IDs that do not belong to a gateway."""

    def __init__(self, settings: Settings) -> None:
        self._plans = _parse_plans(settings.billing_plans_json)

    def list(self) -> list[BillingPlan]:
        return list(self._plans.values())

    def get(self, plan_id: str) -> BillingPlan:
        try:
            return self._plans[plan_id]
        except KeyError as error:
            raise PaymentProviderUnavailable("Unknown billing plan") from error


def _parse_plans(raw_plans: str) -> dict[str, BillingPlan]:
    try:
        candidate = json.loads(raw_plans)
    except json.JSONDecodeError as error:
        raise PaymentProviderUnavailable("Billing plans are not valid JSON") from error
    if not isinstance(candidate, dict):
        raise PaymentProviderUnavailable("Billing plans must be a JSON object")

    plans: dict[str, BillingPlan] = {}
    for plan_id, data in candidate.items():
        if not isinstance(plan_id, str) or not isinstance(data, dict):
            raise PaymentProviderUnavailable("Billing plans contain an invalid entry")
        try:
            plan = BillingPlan(
                id=plan_id,
                name=_as_nonempty_string(data["name"]),
                description=_as_nonempty_string(data["description"]),
                amount_paise=_as_positive_int(data["amount_paise"]),
                currency=_as_nonempty_string(data["currency"]).upper(),
                interval=_as_nonempty_string(data["interval"]),
                total_count=_as_positive_int(data["total_count"]),
            )
        except KeyError as error:
            raise PaymentProviderUnavailable("Billing plan is missing a required field") from error
        plans[plan.id] = plan
    return plans


def _as_nonempty_string(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PaymentProviderUnavailable("Billing plan has an invalid text field")
    return value.strip()


def _as_positive_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PaymentProviderUnavailable("Billing plan has an invalid numeric field")
    return value
