from app.ports.notification_repository import NotificationRepository
from app.ports.summary_generator import SummaryGenerator


class AlertSummaryService:
    def __init__(
        self,
        repository: NotificationRepository,
        summary_generator: SummaryGenerator,
    ) -> None:
        self._repository = repository
        self._summary_generator = summary_generator

    def generate_pending(self, *, limit: int) -> int:
        batches = self._repository.list_missing_summaries(limit=limit)
        generated = 0
        for batch in batches:
            for alert in batch.alerts:
                summary = self._summary_generator.generate(alert.summary_input())
                self._repository.save_summary(
                    alert_id=alert.alert_id,
                    summary=summary,
                    provider=self._summary_generator.provider_name,
                )
                generated += 1
        return generated
