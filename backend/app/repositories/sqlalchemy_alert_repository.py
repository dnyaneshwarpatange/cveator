from collections import defaultdict
from uuid import UUID

from sqlalchemy import and_, exists, func, literal, or_, select, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.orm import Session

from app.domain.alerts import (
    AlertListItem,
    AlertPage,
    AlertProduct,
    AlertStatus,
    DashboardOverview,
    Severity,
    severity_for,
)
from app.models.catalog import Alert, CveProductMatch, Product, WatchlistItem
from app.models.cve import Cve


class SqlAlchemyAlertRepository:
    """System-side adapter that projects global CVE matches into tenant alerts."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create_missing_alerts(self, *, org_id: UUID | None = None) -> int:
        missing_alert = ~exists(
            select(Alert.id).where(
                Alert.org_id == WatchlistItem.org_id,
                Alert.cve_id == CveProductMatch.cve_id,
            )
        )
        candidates = (
            select(
                WatchlistItem.org_id,
                CveProductMatch.cve_id,
                literal(AlertStatus.NEW.value),
            )
            .join(CveProductMatch, CveProductMatch.product_id == WatchlistItem.product_id)
            .where(missing_alert)
            .distinct()
        )
        if org_id is not None:
            candidates = candidates.where(WatchlistItem.org_id == org_id)

        statement = postgresql_insert(Alert).from_select(["org_id", "cve_id", "status"], candidates)
        statement = statement.on_conflict_do_nothing(constraint="uq_alerts_org_cve")
        result = self._session.execute(statement)
        # Psycopg may report -1 for INSERT .. SELECT when the affected count is unknown.
        return max(result.rowcount or 0, 0)


class SqlAlchemyTenantAlertRepository:
    """Tenant boundary for every dashboard alert query and mutation."""

    def __init__(self, session: Session, *, org_id: UUID) -> None:
        self._session = session
        self._org_id = org_id

    def list_alerts(
        self,
        *,
        status: AlertStatus | None,
        severity: Severity | None,
        page: int,
        page_size: int,
    ) -> AlertPage:
        filters = self._filters(status=status, severity=severity)
        total = (
            self._session.scalar(
                select(func.count(Alert.id))
                .join(Cve, Cve.id == Alert.cve_id)
                .where(*filters)
            )
            or 0
        )
        rows = self._session.execute(
            select(Alert, Cve)
            .join(Cve, Cve.id == Alert.cve_id)
            .where(*filters)
            .order_by(Cve.is_kev.desc(), Cve.cvss_score.desc().nullslast(), Alert.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
        if not rows:
            return AlertPage(items=[], total=total)

        product_names = self._products_by_cve_id([cve.id for _, cve in rows])
        items = [
            _to_alert_list_item(alert, cve, product_names.get(cve.id, [])) for alert, cve in rows
        ]
        return AlertPage(items=items, total=total)

    def update_status(self, *, alert_id: int, status: AlertStatus) -> AlertListItem | None:
        updated = self._session.scalar(
            update(Alert)
            .where(Alert.id == alert_id, Alert.org_id == self._org_id)
            .values(status=status.value)
            .returning(Alert)
        )
        if updated is None:
            return None

        cve = self._session.scalar(select(Cve).where(Cve.id == updated.cve_id))
        if cve is None:
            return None
        return _to_alert_list_item(updated, cve, self._products_by_cve_id([cve.id]).get(cve.id, []))

    def overview(self) -> DashboardOverview:
        active_filters = self._filters(status=AlertStatus.NEW, severity=None)
        critical_filters = self._filters(status=AlertStatus.NEW, severity=Severity.CRITICAL)
        kev_filters = [
            Alert.org_id == self._org_id,
            Alert.status == AlertStatus.NEW.value,
            current_watchlist_match(),
            Cve.is_kev,
        ]
        watched_products = (
            self._session.scalar(
                select(func.count(WatchlistItem.id)).where(WatchlistItem.org_id == self._org_id)
            )
            or 0
        )
        active_alerts = (
            self._session.scalar(select(func.count(Alert.id)).where(*active_filters)) or 0
        )
        critical_alerts = (
            self._session.scalar(
                select(func.count(Alert.id))
                .join(Cve, Cve.id == Alert.cve_id)
                .where(*critical_filters)
            )
            or 0
        )
        kev_alerts = (
            self._session.scalar(
                select(func.count(Alert.id)).join(Cve, Cve.id == Alert.cve_id).where(*kev_filters)
            )
            or 0
        )
        return DashboardOverview(
            active_alerts=active_alerts,
            critical_alerts=critical_alerts,
            kev_alerts=kev_alerts,
            watched_products=watched_products,
        )

    def _products_by_cve_id(self, cve_ids: list[int]) -> dict[int, list[AlertProduct]]:
        if not cve_ids:
            return {}
        rows = self._session.execute(
            select(CveProductMatch.cve_id, Product)
            .join(Product, Product.id == CveProductMatch.product_id)
            .join(WatchlistItem, WatchlistItem.product_id == Product.id)
            .where(
                CveProductMatch.cve_id.in_(cve_ids),
                WatchlistItem.org_id == self._org_id,
            )
            .order_by(Product.vendor, Product.product_name, Product.cpe_version)
        ).all()
        products: dict[int, list[AlertProduct]] = defaultdict(list)
        seen: set[tuple[int, int]] = set()
        for cve_id, product in rows:
            key = (cve_id, product.id)
            if key in seen:
                continue
            seen.add(key)
            products[cve_id].append(
                AlertProduct(
                    id=product.id,
                    vendor=product.vendor,
                    product_name=product.product_name,
                    version=product.cpe_version,
                )
            )
        return products

    def _filters(self, *, status: AlertStatus | None, severity: Severity | None) -> list[object]:
        filters: list[object] = [Alert.org_id == self._org_id, current_watchlist_match()]
        if status is not None:
            filters.append(Alert.status == status.value)
        if severity is not None:
            filters.append(_severity_condition(severity))
        return filters


def current_watchlist_match():
    """Historical alerts remain stored but only current subscriptions are actionable."""
    return exists(select(WatchlistItem.id).join(
        CveProductMatch, CveProductMatch.product_id == WatchlistItem.product_id
    ).where(WatchlistItem.org_id == Alert.org_id, CveProductMatch.cve_id == Alert.cve_id))


def _severity_condition(severity: Severity) -> object:
    if severity is Severity.CRITICAL:
        return or_(Cve.is_kev, Cve.cvss_score >= 9)
    if severity is Severity.HIGH:
        return and_(Cve.is_kev.is_(False), Cve.cvss_score >= 7, Cve.cvss_score < 9)
    if severity is Severity.MEDIUM:
        return and_(Cve.is_kev.is_(False), Cve.cvss_score >= 4, Cve.cvss_score < 7)
    if severity is Severity.LOW:
        return and_(Cve.is_kev.is_(False), Cve.cvss_score < 4)
    return and_(Cve.is_kev.is_(False), Cve.cvss_score.is_(None))


def _to_alert_list_item(alert: Alert, cve: Cve, products: list[AlertProduct]) -> AlertListItem:
    return AlertListItem(
        id=alert.id,
        cve_id=cve.cve_id,
        status=AlertStatus(alert.status),
        severity=severity_for(cvss_score=cve.cvss_score, is_kev=cve.is_kev),
        cvss_score=cve.cvss_score,
        epss_score=cve.epss_score,
        is_kev=cve.is_kev,
        published_at=cve.published_at,
        matched_at=None,
        created_at=alert.created_at,
        summary=alert.plain_summary,
        summary_provider=alert.summary_provider,
        products=products,
    )
