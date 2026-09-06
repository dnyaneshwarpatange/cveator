from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from app.domain.summary import AlertSummaryInput


class DeliveryKind(StrEnum):
    REALTIME = "realtime"
    DIGEST = "digest"


@dataclass(frozen=True, slots=True)
class NotificationAlert:
    alert_id: int
    cve_id: str
    cvss_score: float | None
    epss_score: float | None
    is_kev: bool
    published_at: datetime | None
    products: tuple[str, ...]
    summary: str | None

    def summary_input(self) -> AlertSummaryInput:
        return AlertSummaryInput(
            cve_id=self.cve_id,
            cvss_score=self.cvss_score,
            epss_score=self.epss_score,
            is_kev=self.is_kev,
            published_at=self.published_at,
            products=self.products,
        )


@dataclass(frozen=True, slots=True)
class NotificationBatch:
    org_id: UUID
    organization_name: str
    recipients: tuple[str, ...]
    alerts: tuple[NotificationAlert, ...]


@dataclass(frozen=True, slots=True)
class OutboundEmail:
    recipient: str
    subject: str
    text_body: str
    html_body: str


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    alerts_found: int = 0
    alerts_marked_sent: int = 0
    emails_sent: int = 0
    emails_failed: int = 0
    organizations_without_recipients: int = 0
