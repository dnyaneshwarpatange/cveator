import smtplib
from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest
from sqlalchemy.dialects import postgresql

from app.adapters.deterministic_summary import DeterministicSummaryGenerator
from app.adapters.smtp_email import SmtpConfiguration, SmtpEmailSender
from app.core.config import Settings
from app.domain.notifications import (
    DeliveryKind,
    NotificationAlert,
    NotificationBatch,
)
from app.models.catalog import Alert, Organization, Product
from app.models.cve import Cve
from app.repositories.sqlalchemy_notification_repository import (
    SqlAlchemyNotificationRepository,
)
from app.services.notification_composer import NotificationComposer
from app.services.notifications import NotificationDeliveryService


class FakeNotificationRepository:
    def __init__(self, batch: NotificationBatch) -> None:
        self.batch = batch
        self.requested_kind: DeliveryKind | None = None
        self.saved_summaries: dict[int, tuple[str, str]] = {}
        self.marked_sent: tuple[int, ...] = ()

    def list_pending(self, *, kind: DeliveryKind, limit: int) -> list[NotificationBatch]:
        self.requested_kind = kind
        assert limit == 100
        return [self.batch]

    def list_missing_summaries(self, *, limit: int) -> list[NotificationBatch]:
        assert limit == 100
        return [self.batch]

    def save_summary(self, *, alert_id: int, summary: str, provider: str) -> None:
        self.saved_summaries[alert_id] = (summary, provider)

    def mark_sent(self, *, alert_ids: tuple[int, ...], sent_at: datetime) -> None:
        assert sent_at.tzinfo is not None
        self.marked_sent = alert_ids


class RecordingEmailSender:
    def __init__(self, *, fail_recipient: str | None = None) -> None:
        self.fail_recipient = fail_recipient
        self.messages = []

    def send(self, message) -> None:
        if message.recipient == self.fail_recipient:
            raise smtplib.SMTPException("temporary rejection")
        self.messages.append(message)


def test_daily_digest_generates_and_stores_summary_then_marks_alerts_sent() -> None:
    repository = FakeNotificationRepository(_batch())
    sender = RecordingEmailSender()
    service = NotificationDeliveryService(
        repository,
        sender,
        DeterministicSummaryGenerator(),
        NotificationComposer(public_app_url="https://monitor.example.com"),
    )

    result = service.deliver_digest(limit=100)

    assert repository.requested_kind is DeliveryKind.DIGEST
    assert repository.marked_sent == (10, 11)
    assert repository.saved_summaries[10][1] == "deterministic-v1"
    assert len(sender.messages) == 2
    assert all("Daily vulnerability digest" in message.subject for message in sender.messages)
    assert result.alerts_marked_sent == 2
    assert result.emails_sent == 2
    assert result.emails_failed == 0


def test_partial_recipient_failure_leaves_alert_pending_for_retry() -> None:
    repository = FakeNotificationRepository(_batch())
    sender = RecordingEmailSender(fail_recipient="viewer@example.com")
    service = NotificationDeliveryService(
        repository,
        sender,
        DeterministicSummaryGenerator(),
        NotificationComposer(public_app_url="https://monitor.example.com"),
    )

    result = service.deliver_realtime(limit=100)

    assert repository.requested_kind is DeliveryKind.REALTIME
    assert repository.marked_sent == ()
    assert result.emails_sent == 1
    assert result.emails_failed == 1


def test_deterministic_summary_prioritizes_known_active_exploitation() -> None:
    alert = _batch().alerts[0]

    summary = DeterministicSummaryGenerator().generate(alert.summary_input())

    assert "known to be actively exploited" in summary
    assert "Acme Firewall 4.2" in summary
    assert "apply the vendor fix" in summary


def test_pending_realtime_query_locks_only_urgent_unsent_alerts() -> None:
    session = Mock()
    session.execute.return_value.all.return_value = []

    assert (
        SqlAlchemyNotificationRepository(session).list_pending(
            kind=DeliveryKind.REALTIME, limit=25
        )
        == []
    )

    statement = session.execute.call_args.args[0]
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "alerts.sent_at IS NULL" in sql
    assert "alerts.status" in sql
    assert "cves.is_kev" in sql
    assert "cves.cvss_score" in sql
    assert "FOR UPDATE OF alerts SKIP LOCKED" in sql


def test_notification_repository_hydrates_tenant_products_and_active_recipients() -> None:
    org_id = uuid4()
    organization = Organization(id=org_id, name="Acme IT")
    alert = Alert(id=10, org_id=org_id, cve_id=20, status="new")
    cve = Cve(
        id=20,
        cve_id="CVE-2026-1000",
        source_json={},
        cvss_score=9.8,
        epss_score=0.7,
        is_kev=False,
    )
    product = Product(
        id=30,
        part="a",
        vendor="Acme",
        product_name="Firewall",
        cpe_product="firewall",
        cpe_version="4.2",
        cpe_string="cpe:2.3:a:acme:firewall:4.2:*:*:*:*:*:*:*",
    )
    selected = Mock()
    selected.all.return_value = [(alert, cve, organization)]
    recipient_rows = Mock()
    recipient_rows.all.return_value = [(org_id, "owner@example.com")]
    product_rows = Mock()
    product_rows.all.return_value = [(org_id, 20, product)]
    session = Mock()
    session.execute.side_effect = [selected, recipient_rows, product_rows]

    batches = SqlAlchemyNotificationRepository(session).list_pending(
        kind=DeliveryKind.DIGEST, limit=100
    )

    assert len(batches) == 1
    assert batches[0].recipients == ("owner@example.com",)
    assert batches[0].alerts[0].products == ("Acme Firewall 4.2",)


def test_smtp_adapter_uses_starttls_auth_and_one_envelope_recipient(monkeypatch) -> None:
    smtp = FakeSmtpClient()
    monkeypatch.setattr(smtplib, "SMTP", lambda *args, **kwargs: smtp)
    sender = SmtpEmailSender(
        SmtpConfiguration(
            host="smtp.internal",
            port=587,
            security="starttls",
            from_address="alerts@example.com",
            from_name="Security Monitor",
            username="monitor",
            password="secret",
        )
    )
    message = NotificationComposer(public_app_url="https://monitor.example.com").compose(
        kind=DeliveryKind.REALTIME,
        batch=_batch(),
        recipient="owner@example.com",
    )

    sender.send(message)

    assert smtp.started_tls
    assert smtp.login_credentials == ("monitor", "secret")
    assert smtp.to_addrs == ["owner@example.com"]
    assert smtp.message["To"] == "owner@example.com"
    assert smtp.message.get_body(preferencelist=("html",)) is not None
    assert smtp.quit_called


def test_email_configuration_is_required_only_when_delivery_is_enabled() -> None:
    Settings(email_delivery_enabled=False).validate_email_configuration()

    with pytest.raises(RuntimeError, match="SMTP_HOST"):
        Settings(
            email_delivery_enabled=True,
            smtp_host="",
            email_from_address="",
        ).validate_email_configuration()


class FakeSmtpClient:
    def __init__(self) -> None:
        self.started_tls = False
        self.login_credentials: tuple[str, str] | None = None
        self.to_addrs: list[str] = []
        self.message = None
        self.quit_called = False

    def ehlo(self) -> None:
        return None

    def starttls(self, *, context) -> None:
        self.started_tls = True

    def login(self, username: str, password: str) -> None:
        self.login_credentials = (username, password)

    def send_message(self, message, *, from_addr: str, to_addrs: list[str]) -> None:
        assert from_addr == "alerts@example.com"
        self.message = message
        self.to_addrs = to_addrs

    def quit(self) -> None:
        self.quit_called = True

    def close(self) -> None:
        return None


def _batch() -> NotificationBatch:
    org_id: UUID = uuid4()
    return NotificationBatch(
        org_id=org_id,
        organization_name="Acme IT",
        recipients=("owner@example.com", "viewer@example.com"),
        alerts=(
            NotificationAlert(
                alert_id=10,
                cve_id="CVE-2026-1000",
                cvss_score=8.1,
                epss_score=0.7,
                is_kev=True,
                published_at=datetime(2026, 9, 4, tzinfo=UTC),
                products=("Acme Firewall 4.2",),
                summary=None,
            ),
            NotificationAlert(
                alert_id=11,
                cve_id="CVE-2026-1001",
                cvss_score=9.8,
                epss_score=0.2,
                is_kev=False,
                published_at=datetime(2026, 9, 4, tzinfo=UTC),
                products=("Acme Router 2",),
                summary="Apply the current vendor update.",
            ),
        ),
    )
