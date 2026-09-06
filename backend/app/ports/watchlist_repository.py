from typing import Protocol

from app.domain.watchlist import WatchlistProduct


class WatchlistRepository(Protocol):
    def list_products(self) -> list[WatchlistProduct]: ...

    def add_product(self, product_id: int) -> WatchlistProduct | None: ...

    def remove_product(self, product_id: int) -> bool: ...
