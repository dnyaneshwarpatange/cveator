from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class AlertSummaryInput:
    """Vendor-neutral input to a future plain-language summary adapter."""

    cve_id: str
    cvss_score: float | None
    epss_score: float | None
    is_kev: bool
    published_at: datetime | None
    products: tuple[str, ...]
