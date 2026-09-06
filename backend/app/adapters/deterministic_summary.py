from app.domain.summary import AlertSummaryInput


class DeterministicSummaryGenerator:
    """Plain-language fallback that works without an external model API."""

    provider_name = "deterministic-v1"

    def generate(self, alert: AlertSummaryInput) -> str:
        affected = _affected_products(alert.products)
        if alert.is_kev:
            return (
                f"{alert.cve_id} is known to be actively exploited and may affect {affected}. "
                "Check exposure now, apply the vendor fix, or isolate the software until it is "
                "patched."
            )
        if alert.cvss_score is not None and alert.cvss_score >= 9:
            return (
                f"{alert.cve_id} is rated critical and may affect {affected}. Prioritize the "
                "vendor update and reduce network access until the fix is applied."
            )
        if alert.epss_score is not None and alert.epss_score >= 0.1:
            return (
                f"{alert.cve_id} may affect {affected} and has an elevated likelihood of being "
                "exploited. Review vendor guidance and schedule the update promptly."
            )
        return (
            f"{alert.cve_id} may affect {affected}. Confirm the installed version, review the "
            "vendor guidance, and apply the recommended update."
        )


def _affected_products(products: tuple[str, ...]) -> str:
    if not products:
        return "software on your watchlist"
    if len(products) == 1:
        return products[0]
    if len(products) == 2:
        return f"{products[0]} and {products[1]}"
    return f"{products[0]}, {products[1]}, and {len(products) - 2} other watched products"
