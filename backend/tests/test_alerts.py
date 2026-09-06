from unittest.mock import Mock
from uuid import uuid4

from sqlalchemy.dialects import postgresql

from app.domain.alerts import AlertStatus, Severity, severity_for
from app.repositories.sqlalchemy_alert_repository import (
    SqlAlchemyAlertRepository,
    SqlAlchemyTenantAlertRepository,
)


def test_severity_prioritizes_known_exploitation_over_the_numeric_score() -> None:
    assert severity_for(cvss_score=2.1, is_kev=True) is Severity.CRITICAL
    assert severity_for(cvss_score=9.0, is_kev=False) is Severity.CRITICAL
    assert severity_for(cvss_score=7.0, is_kev=False) is Severity.HIGH
    assert severity_for(cvss_score=4.0, is_kev=False) is Severity.MEDIUM
    assert severity_for(cvss_score=3.9, is_kev=False) is Severity.LOW
    assert severity_for(cvss_score=None, is_kev=False) is Severity.UNKNOWN


def test_alert_projection_is_idempotent_and_uses_the_watchlist_tenant() -> None:
    session = Mock()
    session.execute.return_value.rowcount = 3

    created = SqlAlchemyAlertRepository(session).create_missing_alerts(org_id=uuid4())

    assert created == 3
    statement = session.execute.call_args.args[0]
    compiled = statement.compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert "INSERT INTO alerts" in sql
    assert "uq_alerts_org_cve" in sql
    assert "watchlist_items.org_id" in sql


def test_alert_projection_never_reports_psycopg_unknown_rowcount_as_negative() -> None:
    session = Mock()
    session.execute.return_value.rowcount = -1

    assert SqlAlchemyAlertRepository(session).create_missing_alerts() == 0


def test_alert_status_update_cannot_escape_the_current_organization() -> None:
    session = Mock()
    session.scalar.return_value = None
    org_id = uuid4()

    updated = SqlAlchemyTenantAlertRepository(session, org_id=org_id).update_status(
        alert_id=42, status=AlertStatus.READ
    )

    assert updated is None
    statement = session.scalar.call_args.args[0]
    compiled = statement.compile(dialect=postgresql.dialect())
    assert "alerts.org_id" in str(compiled)
    assert org_id in compiled.params.values()


def test_severity_filtered_alert_count_joins_the_cve_table() -> None:
    session = Mock()
    session.scalar.return_value = 0
    session.execute.return_value.all.return_value = []

    SqlAlchemyTenantAlertRepository(session, org_id=uuid4()).list_alerts(
        status=AlertStatus.NEW, severity=Severity.CRITICAL, page=1, page_size=10
    )

    count_statement = session.scalar.call_args.args[0]
    sql = str(count_statement.compile(dialect=postgresql.dialect()))
    assert "JOIN cves ON cves.id = alerts.cve_id" in sql
