from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class AlertStatus(StrEnum):
    NEW = "new"
    READ = "read"
    DISMISSED = "dismissed"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


def severity_for(*, cvss_score: float | None, is_kev: bool) -> Severity:
    """Keep a single, explicit severity policy for API and dashboard consumers."""
    if is_kev or (cvss_score is not None and cvss_score >= 9):
        return Severity.CRITICAL
    if cvss_score is None:
        return Severity.UNKNOWN
    if cvss_score >= 7:
        return Severity.HIGH
    if cvss_score >= 4:
        return Severity.MEDIUM
    return Severity.LOW


@dataclass(frozen=True, slots=True)
class AlertProduct:
    id: int
    vendor: str
    product_name: str
    version: str


@dataclass(frozen=True, slots=True)
class AlertListItem:
    id: int
    cve_id: str
    status: AlertStatus
    severity: Severity
    cvss_score: float | None
    epss_score: float | None
    is_kev: bool
    published_at: datetime | None
    matched_at: datetime | None
    created_at: datetime
    summary: str | None
    summary_provider: str | None
    products: list[AlertProduct]


@dataclass(frozen=True, slots=True)
class AlertPage:
    items: list[AlertListItem]
    total: int


@dataclass(frozen=True, slots=True)
class DashboardOverview:
    active_alerts: int
    critical_alerts: int
    kev_alerts: int
    watched_products: int
