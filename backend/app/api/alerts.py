from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_principal, require_monitoring_access, require_roles
from app.db.session import get_session
from app.domain.alerts import AlertListItem, AlertStatus, DashboardOverview, Severity
from app.domain.auth import OrganizationRole, Principal
from app.repositories.sqlalchemy_alert_repository import SqlAlchemyTenantAlertRepository

router = APIRouter(
    prefix="/alerts", tags=["alerts"], dependencies=[Depends(require_monitoring_access)]
)


class AlertProductResponse(BaseModel):
    id: int
    vendor: str
    product_name: str
    version: str


class AlertResponse(BaseModel):
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
    products: list[AlertProductResponse]


class AlertPageResponse(BaseModel):
    items: list[AlertResponse]
    total: int
    page: int
    page_size: int


class UpdateAlertRequest(BaseModel):
    status: AlertStatus


class DashboardOverviewResponse(BaseModel):
    active_alerts: int
    critical_alerts: int
    kev_alerts: int
    watched_products: int


@router.get("", response_model=AlertPageResponse)
def list_alerts(
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_session)],
    alert_status: Annotated[AlertStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
) -> AlertPageResponse:
    alerts = SqlAlchemyTenantAlertRepository(session, org_id=principal.org_id).list_alerts(
        status=alert_status,
        severity=severity,
        page=page,
        page_size=page_size,
    )
    return AlertPageResponse(
        items=[_alert_response(alert) for alert in alerts.items],
        total=alerts.total,
        page=page,
        page_size=page_size,
    )


@router.get("/dashboard/overview", response_model=DashboardOverviewResponse)
def dashboard_overview(
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> DashboardOverviewResponse:
    overview = SqlAlchemyTenantAlertRepository(session, org_id=principal.org_id).overview()
    return _overview_response(overview)


@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert(
    alert_id: int,
    payload: UpdateAlertRequest,
    principal: Annotated[
        Principal,
        Depends(
            require_roles(
                OrganizationRole.OWNER,
                OrganizationRole.ADMIN,
                OrganizationRole.MEMBER,
            )
        ),
    ],
    session: Annotated[Session, Depends(get_session)],
) -> AlertResponse:
    repository = SqlAlchemyTenantAlertRepository(session, org_id=principal.org_id)
    try:
        alert = repository.update_status(alert_id=alert_id, status=payload.status)
        if alert is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
        session.commit()
    except HTTPException:
        session.rollback()
        raise
    except Exception:
        session.rollback()
        raise
    return _alert_response(alert)


def _alert_response(alert: AlertListItem) -> AlertResponse:
    return AlertResponse(
        id=alert.id,
        cve_id=alert.cve_id,
        status=alert.status,
        severity=alert.severity,
        cvss_score=alert.cvss_score,
        epss_score=alert.epss_score,
        is_kev=alert.is_kev,
        published_at=alert.published_at,
        matched_at=alert.matched_at,
        created_at=alert.created_at,
        summary=alert.summary,
        summary_provider=alert.summary_provider,
        products=[
            AlertProductResponse(
                id=product.id,
                vendor=product.vendor,
                product_name=product.product_name,
                version=product.version,
            )
            for product in alert.products
        ],
    )


def _overview_response(overview: DashboardOverview) -> DashboardOverviewResponse:
    return DashboardOverviewResponse(
        active_alerts=overview.active_alerts,
        critical_alerts=overview.critical_alerts,
        kev_alerts=overview.kev_alerts,
        watched_products=overview.watched_products,
    )
