from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from app.domain.product import CatalogFetchResult, CatalogPage
from app.ports.catalog_repository import CatalogRepository


class CatalogFeed(Protocol):
    source_name: str

    def fetch_since(self, since: datetime) -> CatalogFetchResult: ...


class PagedCatalogFeed(Protocol):
    source_name: str

    def iter_pages(self, *, since: datetime) -> Iterator[CatalogPage]: ...


@dataclass(frozen=True, slots=True)
class CatalogSyncSummary:
    source: str
    products_upserted: int
    high_watermark: datetime


class ProductCatalogSyncService:
    def __init__(self, repository: CatalogRepository, initial_cursors: dict[str, datetime]) -> None:
        self._repository = repository
        self._initial_cursors = initial_cursors

    def sync(self, feed: CatalogFeed) -> CatalogSyncSummary:
        cursor = (
            self._repository.get_cursor(feed.source_name) or self._initial_cursors[feed.source_name]
        )
        result = feed.fetch_since(cursor)
        for product in result.products:
            self._repository.upsert_product(product)
        self._repository.save_cursor(feed.source_name, result.next_cursor)
        return CatalogSyncSummary(
            source=feed.source_name,
            products_upserted=len(result.products),
            high_watermark=result.next_cursor,
        )

    def sync_pages(
        self, feed: PagedCatalogFeed, *, commit_page: Callable[[], None]
    ) -> CatalogSyncSummary:
        cursor = (
            self._repository.get_cursor(feed.source_name) or self._initial_cursors[feed.source_name]
        )
        count = 0
        for page in feed.iter_pages(since=cursor):
            count += self._repository.upsert_products(page.products)
            if page.complete:
                cursor = page.window_end
                self._repository.save_cursor(feed.source_name, cursor)
            commit_page()
        return CatalogSyncSummary(feed.source_name, count, cursor)
