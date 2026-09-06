from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.domain.watchlist import WatchlistProduct
from app.models.catalog import Product, WatchlistItem


class SqlAlchemyWatchlistRepository:
    """The tenant boundary lives here, not in individual request handlers."""

    def __init__(self, session: Session, *, org_id: UUID) -> None:
        self._session = session
        self._org_id = org_id

    def list_products(self) -> list[WatchlistProduct]:
        statement = (
            select(Product)
            .join(WatchlistItem, WatchlistItem.product_id == Product.id)
            .where(WatchlistItem.org_id == self._org_id)
            .order_by(Product.vendor, Product.product_name, Product.cpe_version)
        )
        return [_to_watchlist_product(product) for product in self._session.scalars(statement)]

    def add_product(self, product_id: int) -> WatchlistProduct | None:
        product = self._session.scalar(select(Product).where(Product.id == product_id))
        if product is None:
            return None
        statement = insert(WatchlistItem).values(org_id=self._org_id, product_id=product_id)
        statement = statement.on_conflict_do_nothing(constraint="uq_watchlist_items_org_product")
        self._session.execute(statement)
        return _to_watchlist_product(product)

    def remove_product(self, product_id: int) -> bool:
        statement = delete(WatchlistItem).where(
            WatchlistItem.org_id == self._org_id,
            WatchlistItem.product_id == product_id,
        )
        result = self._session.execute(statement)
        return bool(result.rowcount)


def _to_watchlist_product(product: Product) -> WatchlistProduct:
    return WatchlistProduct(
        id=product.id,
        vendor=product.vendor,
        product_name=product.product_name,
        version=product.cpe_version,
    )
