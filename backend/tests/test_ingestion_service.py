from datetime import UTC, datetime

import pytest

from app.domain.cve import FetchResult, NormalizedCve
from app.services.ingestion import CveIngestionService


class FakeRepository:
    def __init__(self, *, fail_on_upsert: bool = False) -> None:
        self.cursors: dict[str, datetime] = {}
        self.records: list[NormalizedCve] = []
        self.reconciled_ids: set[str] | None = None
        self.fail_on_upsert = fail_on_upsert

    def get_cursor(self, source: str) -> datetime | None:
        return self.cursors.get(source)

    def save_cursor(self, source: str, high_watermark: datetime) -> None:
        self.cursors[source] = high_watermark

    def upsert_cve(self, record: NormalizedCve) -> None:
        if self.fail_on_upsert:
            raise RuntimeError("database write failed")
        self.records.append(record)

    def reconcile_kev(self, active_cve_ids: set[str]) -> None:
        self.reconciled_ids = active_cve_ids


class StaticFeed:
    def __init__(self, source_name: str, result: FetchResult) -> None:
        self.source_name = source_name
        self._result = result
        self.requested_cursor: datetime | None = None

    def fetch_since(self, since: datetime) -> FetchResult:
        self.requested_cursor = since
        return self._result


def test_service_upserts_before_advancing_cursor_and_reconciles_kev() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    finish = datetime(2026, 1, 2, tzinfo=UTC)
    record = NormalizedCve("CVE-2026-0001", "cisa_kev", {"cveID": "CVE-2026-0001"}, is_kev=True)
    repository = FakeRepository()
    feed = StaticFeed("cisa_kev", FetchResult(records=[record], next_cursor=finish))

    result = CveIngestionService(repository, {"cisa_kev": start}).sync(feed)

    assert feed.requested_cursor == start
    assert repository.records == [record]
    assert repository.reconciled_ids == {"CVE-2026-0001"}
    assert repository.cursors == {"cisa_kev": finish}
    assert result.records_upserted == 1


def test_service_does_not_advance_cursor_after_a_failed_write() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    finish = datetime(2026, 1, 2, tzinfo=UTC)
    record = NormalizedCve("CVE-2026-0001", "nvd", {"cve": {}})
    repository = FakeRepository(fail_on_upsert=True)
    feed = StaticFeed("nvd", FetchResult(records=[record], next_cursor=finish))

    with pytest.raises(RuntimeError, match="database write failed"):
        CveIngestionService(repository, {"nvd": start}).sync(feed)

    assert repository.cursors == {}


def test_service_calls_record_hook_after_persistence() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    finish = datetime(2026, 1, 2, tzinfo=UTC)
    record = NormalizedCve("CVE-2026-0001", "nvd", {"cve": {}})
    repository = FakeRepository()
    feed = StaticFeed("nvd", FetchResult(records=[record], next_cursor=finish))
    observed: list[NormalizedCve] = []

    CveIngestionService(repository, {"nvd": start}).sync(feed, on_record_persisted=observed.append)

    assert repository.records == [record]
    assert observed == [record]


def test_stale_record_does_not_recompute_matches() -> None:
    class StaleRepository(FakeRepository):
        def upsert_cve(self, record: NormalizedCve) -> bool:
            return False

    start = datetime(2026, 1, 1, tzinfo=UTC)
    finish = datetime(2026, 1, 2, tzinfo=UTC)
    record = NormalizedCve("CVE-2026-0001", "nvd", {"cve": {}})
    repository = StaleRepository()
    feed = StaticFeed("nvd", FetchResult(records=[record], next_cursor=finish))
    observed = []
    CveIngestionService(repository, {"nvd": start}).sync(feed, on_record_persisted=observed.append)
    assert observed == []
    assert repository.cursors["nvd"] == finish
