from collections import defaultdict
from datetime import datetime
from uuid import UUID

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.domain.alerts import AlertStatus
from app.domain.notifications import DeliveryKind, NotificationAlert, NotificationBatch
from app.models.catalog import (
    Alert,
    CveProductMatch,
    Organization,
    Product,
    User,
    WatchlistItem,
)
from app.models.cve import Cve
from app.repositories.sqlalchemy_alert_repository import current_watchlist_match
from app.services.access import monitoring_access_condition


class SqlAlchemyNotificationRepository:
    """System job adapter; selected alert rows stay locked through SMTP submission."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_pending(self, *, kind: DeliveryKind, limit: int) -> list[NotificationBatch]:
        conditions: list[object] = [
            current_watchlist_match(),
            Alert.sent_at.is_(None),
            Alert.status == AlertStatus.NEW.value,
        ]
        if kind is DeliveryKind.REALTIME:
            conditions.append(or_(Cve.is_kev, Cve.cvss_score >= 9))

        return self._load_batches(conditions=conditions, limit=limit, include_recipients=True)

    def list_missing_summaries(self, *, limit: int) -> list[NotificationBatch]:
        return self._load_batches(
            conditions=[
                Alert.plain_summary.is_(None),
                Alert.status == AlertStatus.NEW.value,
            ],
            limit=limit,
            include_recipients=False,
        )

    def _load_batches(
        self,
        *,
        conditions: list[object],
        limit: int,
        include_recipients: bool,
    ) -> list[NotificationBatch]:

        rows = self._session.execute(
            select(Alert, Cve, Organization)
            .join(Cve, Cve.id == Alert.cve_id)
            .join(Organization, Organization.id == Alert.org_id)
            .where(*conditions, monitoring_access_condition(Alert.org_id))
            .order_by(Cve.is_kev.desc(), Cve.cvss_score.desc().nullslast(), Alert.created_at)
            .limit(limit)
            .with_for_update(of=Alert, skip_locked=True)
        ).all()
        if not rows:
            return []

        org_ids = {alert.org_id for alert, _, _ in rows}
        cve_ids = {cve.id for _, cve, _ in rows}
        recipients = self._recipients_by_org(org_ids) if include_recipients else {}
        products = self._products_by_org_and_cve(org_ids=org_ids, cve_ids=cve_ids)
        grouped: dict[UUID, list[NotificationAlert]] = defaultdict(list)
        organization_names: dict[UUID, str] = {}

        for alert, cve, organization in rows:
            organization_names[alert.org_id] = organization.name
            grouped[alert.org_id].append(
                NotificationAlert(
                    alert_id=alert.id,
                    cve_id=cve.cve_id,
                    cvss_score=cve.cvss_score,
                    epss_score=cve.epss_score,
                    is_kev=cve.is_kev,
                    published_at=cve.published_at,
                    products=products.get((alert.org_id, cve.id), ()),
                    summary=alert.plain_summary,
                )
            )

        return [
            NotificationBatch(
                org_id=org_id,
                organization_name=organization_names[org_id],
                recipients=recipients.get(org_id, ()),
                alerts=tuple(alerts),
            )
            for org_id, alerts in grouped.items()
        ]

    def save_summary(self, *, alert_id: int, summary: str, provider: str) -> None:
        self._session.execute(
            update(Alert)
            .where(Alert.id == alert_id, Alert.plain_summary.is_(None))
            .values(
                plain_summary=summary,
                summary_provider=provider,
                summary_generated_at=utc_now(),
            )
        )

    def mark_sent(self, *, alert_ids: tuple[int, ...], sent_at: datetime) -> None:
        if not alert_ids:
            return
        self._session.execute(
            update(Alert)
            .where(Alert.id.in_(alert_ids), Alert.sent_at.is_(None))
            .values(sent_at=sent_at)
        )

    def _recipients_by_org(self, org_ids: set[UUID]) -> dict[UUID, tuple[str, ...]]:
        rows = self._session.execute(
            select(User.org_id, User.email)
            .where(User.org_id.in_(org_ids), User.is_active)
            .order_by(User.org_id, User.email)
        ).all()
        recipients: dict[UUID, list[str]] = defaultdict(list)
        seen: set[tuple[UUID, str]] = set()
        for org_id, email in rows:
            key = (org_id, email.casefold())
            if key in seen:
                continue
            seen.add(key)
            recipients[org_id].append(email)
        return {org_id: tuple(addresses) for org_id, addresses in recipients.items()}

    def _products_by_org_and_cve(
        self, *, org_ids: set[UUID], cve_ids: set[int]
    ) -> dict[tuple[UUID, int], tuple[str, ...]]:
        rows = self._session.execute(
            select(WatchlistItem.org_id, CveProductMatch.cve_id, Product)
            .join(Product, Product.id == WatchlistItem.product_id)
            .join(CveProductMatch, CveProductMatch.product_id == Product.id)
            .where(
                WatchlistItem.org_id.in_(org_ids),
                CveProductMatch.cve_id.in_(cve_ids),
            )
            .order_by(Product.vendor, Product.product_name, Product.cpe_version)
        ).all()
        names: dict[tuple[UUID, int], list[str]] = defaultdict(list)
        seen: set[tuple[UUID, int, int]] = set()
        for org_id, cve_id, product in rows:
            identity = (org_id, cve_id, product.id)
            if identity in seen:
                continue
            seen.add(identity)
            label = f"{product.vendor} {product.product_name}"
            if product.cpe_version not in {"", "*", "-"}:
                label = f"{label} {product.cpe_version}"
            names[(org_id, cve_id)].append(label)
        return {key: tuple(value) for key, value in names.items()}
