from typing import Protocol

from app.domain.summary import AlertSummaryInput


class SummaryGenerator(Protocol):
    """Boundary for a future AI or self-hosted summary implementation."""

    provider_name: str

    def generate(self, alert: AlertSummaryInput) -> str:
        """Return a short, plain-language action summary for one alert."""
        ...
