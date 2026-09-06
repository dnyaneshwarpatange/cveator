from collections.abc import Iterable
from datetime import datetime
from typing import Protocol

from app.domain.product import CatalogProduct


class CatalogRepository(Protocol):
    def get_cursor(self, source: str) -> datetime | None: ...

    def save_cursor(self, source: str, high_watermark: datetime) -> None: ...

    def upsert_product(self, product: CatalogProduct) -> None: ...

    def upsert_products(self, products: Iterable[CatalogProduct]) -> int: ...
