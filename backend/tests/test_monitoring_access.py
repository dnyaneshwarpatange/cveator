from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy.dialects import postgresql

from app.api.dependencies import require_monitoring_access
from app.api.intelligence import data_status, without_provenance
from app.services import access


@pytest.mark.parametrize(
    "elapsed,expected",
    [
        (timedelta(days=3, microseconds=-1), "trial"),
        (timedelta(days=3), "expired"),
        (timedelta(days=4), "expired"),
    ],
)
def test_trial_is_exactly_72_hours(monkeypatch, elapsed, expected):
    now = datetime(2026, 9, 8, tzinfo=UTC)
    monkeypatch.setattr(access, "utc_now", lambda: now)
    session = Mock()
    session.scalar.side_effect = [now - elapsed, None]
    result = access.monitoring_access(session, uuid4())
    assert result["status"] == expected
    assert result["has_access"] == (expected == "trial")


def test_paid_period_restores_expired_trial(monkeypatch):
    now = datetime(2026, 9, 8, tzinfo=UTC)
    monkeypatch.setattr(access, "utc_now", lambda: now)
    session = Mock()
    session.scalar.side_effect = [now - timedelta(days=10), now + timedelta(days=30)]
    assert access.monitoring_access(session, uuid4())["status"] == "active"


def test_expired_monitoring_dependency_returns_payment_required(monkeypatch):
    monkeypatch.setattr(access, "monitoring_access", lambda *_: {"has_access": False})
    with pytest.raises(HTTPException) as error:
        require_monitoring_access(SimpleNamespace(org_id=uuid4()), Mock())
    assert error.value.status_code == 402


def test_organization_owner_is_not_application_admin(monkeypatch):
    monkeypatch.setattr(
        access, "get_settings", lambda: SimpleNamespace(application_admin_user_id="")
    )
    with pytest.raises(HTTPException) as error:
        data_status(SimpleNamespace(user_id=uuid4()), Mock())
    assert error.value.status_code == 403


def test_only_configured_immutable_user_id_is_admin(monkeypatch):
    user_id = uuid4()
    monkeypatch.setattr(
        access, "get_settings", lambda: SimpleNamespace(application_admin_user_id=str(user_id))
    )
    assert access.is_application_admin(user_id)
    assert not access.is_application_admin(uuid4())


def test_nested_provenance_removed_without_mutating_original():
    raw = {
        "description": "Keep remediation",
        "description_source": "nvd",
        "affected": [{"product": "jira", "source": "mitre"}],
        "changes": {"cvss": {"old": {"score": 8, "source": "nvd"}}},
        "source_modified_at": "2026-09-08",
    }
    clean = without_provenance(raw)
    assert "source" not in str(clean)
    assert clean["affected"] == [{"product": "jira"}]
    assert raw["affected"][0]["source"] == "mitre"


def test_background_filter_requires_org_scoped_webhook_confirmed_future_period():
    from app.models.catalog import Alert

    sql = str(
        access.monitoring_access_condition(Alert.org_id).compile(dialect=postgresql.dialect())
    )
    assert "subscriptions.org_id = alerts.org_id" in sql
    assert "subscriptions.current_period_end >" in sql
    assert "subscriptions.last_provider_event_at IS NOT NULL" in sql
