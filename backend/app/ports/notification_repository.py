from datetime import datetime
from typing import Protocol

from app.domain.notifications import DeliveryKind, NotificationBatch


class NotificationRepository(Protocol):
    def list_pending(
        self, *, kind: DeliveryKind, limit: int
    ) -> list[NotificationBatch]: ...

    def list_missing_summaries(self, *, limit: int) -> list[NotificationBatch]: ...

    def save_summary(self, *, alert_id: int, summary: str, provider: str) -> None: ...

    def mark_sent(self, *, alert_ids: tuple[int, ...], sent_at: datetime) -> None: ...
