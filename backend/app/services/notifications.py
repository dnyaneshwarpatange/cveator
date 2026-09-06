import logging
from dataclasses import replace

from app.core.time import utc_now
from app.domain.notifications import DeliveryKind, DeliveryResult, NotificationBatch
from app.ports.email_sender import EmailSender
from app.ports.notification_repository import NotificationRepository
from app.ports.summary_generator import SummaryGenerator
from app.services.notification_composer import NotificationComposer

logger = logging.getLogger(__name__)


class NotificationDeliveryService:
    def __init__(
        self,
        repository: NotificationRepository,
        email_sender: EmailSender,
        summary_generator: SummaryGenerator,
        composer: NotificationComposer,
    ) -> None:
        self._repository = repository
        self._email_sender = email_sender
        self._summary_generator = summary_generator
        self._composer = composer

    def deliver_realtime(self, *, limit: int) -> DeliveryResult:
        return self._deliver(kind=DeliveryKind.REALTIME, limit=limit)

    def deliver_digest(self, *, limit: int) -> DeliveryResult:
        return self._deliver(kind=DeliveryKind.DIGEST, limit=limit)

    def _deliver(self, *, kind: DeliveryKind, limit: int) -> DeliveryResult:
        batches = self._repository.list_pending(kind=kind, limit=limit)
        alerts_found = sum(len(batch.alerts) for batch in batches)
        alerts_marked_sent = 0
        emails_sent = 0
        emails_failed = 0
        organizations_without_recipients = 0

        for batch in batches:
            hydrated = self._ensure_summaries(batch)
            if not hydrated.recipients:
                organizations_without_recipients += 1
                continue

            all_recipients_succeeded = True
            for recipient in hydrated.recipients:
                try:
                    self._email_sender.send(
                        self._composer.compose(kind=kind, batch=hydrated, recipient=recipient)
                    )
                    emails_sent += 1
                except Exception:
                    all_recipients_succeeded = False
                    emails_failed += 1
                    logger.exception(
                        "Transactional email delivery failed",
                        extra={"org_id": str(hydrated.org_id), "delivery_kind": kind.value},
                    )

            if all_recipients_succeeded:
                alert_ids = tuple(alert.alert_id for alert in hydrated.alerts)
                self._repository.mark_sent(alert_ids=alert_ids, sent_at=utc_now())
                alerts_marked_sent += len(alert_ids)

        return DeliveryResult(
            alerts_found=alerts_found,
            alerts_marked_sent=alerts_marked_sent,
            emails_sent=emails_sent,
            emails_failed=emails_failed,
            organizations_without_recipients=organizations_without_recipients,
        )

    def _ensure_summaries(self, batch: NotificationBatch) -> NotificationBatch:
        alerts = []
        for alert in batch.alerts:
            if alert.summary:
                alerts.append(alert)
                continue
            summary = self._summary_generator.generate(alert.summary_input())
            self._repository.save_summary(
                alert_id=alert.alert_id,
                summary=summary,
                provider=self._summary_generator.provider_name,
            )
            alerts.append(replace(alert, summary=summary))
        return replace(batch, alerts=tuple(alerts))
