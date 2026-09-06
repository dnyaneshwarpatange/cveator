from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from app.domain.cve import FetchResult, NormalizedCve
from app.ports.cve_feed import CveFeed
from app.ports.cve_repository import CveRepository


@dataclass(frozen=True, slots=True)
class SyncSummary:
    source: str
    records_upserted: int
    high_watermark: datetime


class CveIngestionService:
    """Application service with no knowledge of HTTP clients or SQLAlchemy."""

    def __init__(self, repository: CveRepository, initial_cursors: dict[str, datetime]) -> None:
        self._repository = repository
        self._initial_cursors = initial_cursors

    def sync(
        self,
        feed: CveFeed,
        *,
        on_record_persisted: Callable[[NormalizedCve], None] | None = None,
    ) -> SyncSummary:
        cursor = self._repository.get_cursor(feed.source_name)
        if cursor is None:
            cursor = self._initial_cursors[feed.source_name]

        result = feed.fetch_since(cursor)
        self._persist_result(feed.source_name, result, on_record_persisted=on_record_persisted)
        return SyncSummary(
            source=feed.source_name,
            records_upserted=len(result.records),
            high_watermark=result.next_cursor,
        )

    def _persist_result(
        self,
        source: str,
        result: FetchResult,
        *,
        on_record_persisted: Callable[[NormalizedCve], None] | None,
    ) -> None:
        for record in result.records:
            accepted = self._repository.upsert_cve(record)
            if accepted is not False and on_record_persisted is not None:
                on_record_persisted(record)
        if source == "cisa_kev":
            self._repository.reconcile_kev({record.cve_id for record in result.records})
        # Persist this last: a failed record must be retried in the next run.
        self._repository.save_cursor(source, result.next_cursor)
