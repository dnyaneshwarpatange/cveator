import re
from collections.abc import Iterable
from dataclasses import asdict
from datetime import datetime

from sqlalchemy import Select, and_, case, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.domain.product import CatalogProduct, product_name_query
from app.models.catalog import Product
from app.models.cve import IngestionCursor


def product_family(product: CatalogProduct) -> CatalogProduct:
    """Keep escaped CPE identity bytes, replacing all version/platform fields with ANY."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in product.cpe_string:
        if character == ":" and not escaped:
            fields.append("".join(current))
            current = []
            if len(fields) == 5:
                break
        else:
            current.append(character)
        escaped = character == "\\" and not escaped
    if len(fields) != 5:
        raise ValueError("Cannot derive a family from an invalid CPE")
    return CatalogProduct(
        part=product.part, vendor=product.vendor,
        product_name=product.cpe_product.replace("_", " ").title(),
        cpe_product=product.cpe_product, cpe_version="*",
        cpe_string=":".join([*fields, *(["*"] * 8)]),
    )


class SqlAlchemyCatalogRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_cursor(self, source: str) -> datetime | None:
        return self._session.scalar(
            select(IngestionCursor.high_watermark).where(IngestionCursor.source == source)
        )

    def save_cursor(self, source: str, high_watermark: datetime) -> None:
        cursor = self._session.scalar(
            select(IngestionCursor).where(IngestionCursor.source == source)
        )
        if cursor is None:
            self._session.add(IngestionCursor(source=source, high_watermark=high_watermark))
        else:
            cursor.high_watermark = high_watermark

    def upsert_product(self, product: CatalogProduct) -> None:
        self.upsert_products([product])

    def upsert_products(self, products: Iterable[CatalogProduct]) -> int:
        rows: dict[str, dict[str, object]] = {}
        families: dict[str, dict[str, object]] = {}
        count = 0
        for product in products:
            rows[product.cpe_string] = {**asdict(product), "is_family": False}
            family = product_family(product)
            families[family.cpe_string] = {**asdict(family), "is_family": True}
            count += 1
        # Generic entries can already exist in the official dictionary. Deduplicate
        # them before the batch insert so one CPE never conflicts twice in one query.
        rows.update(families)
        self._upsert_rows(list(rows.values()))
        return count

    def _upsert_rows(self, rows: list[dict[str, object]]) -> None:
        columns = ("part", "vendor", "product_name", "cpe_product", "cpe_version", "is_family")
        for offset in range(0, len(rows), 1000):
            statement = insert(Product).values(rows[offset:offset + 1000])
            self._session.execute(statement.on_conflict_do_update(
                index_elements=[Product.cpe_string],
                set_={column: getattr(statement.excluded, column) for column in columns},
                where=or_(*(getattr(Product, column).is_distinct_from(
                    getattr(statement.excluded, column)) for column in columns)),
            ))

    def backfill_families(self, *, batch_size: int = 5000) -> int:
        """Derive families from an existing catalog using bounded keyset pages."""
        upper_id = self._session.scalar(select(func.max(Product.id))) or 0
        last_id = 0
        count = 0
        while last_id < upper_id:
            batch = list(self._session.scalars(
                select(Product).where(Product.id > last_id, Product.id <= upper_id)
                .order_by(Product.id).limit(batch_size)
            ))
            if not batch:
                break
            families: dict[str, dict[str, object]] = {}
            for product in batch:
                if product.part == "*" or product.cpe_product == "*":
                    continue  # Synthetic vendor subscriptions are not product families.
                family = product_family(CatalogProduct(
                    part=product.part, vendor=product.vendor, product_name=product.product_name,
                    cpe_product=product.cpe_product, cpe_version=product.cpe_version,
                    cpe_string=product.cpe_string,
                ))
                families[family.cpe_string] = {**asdict(family), "is_family": True}
            self._upsert_rows(list(families.values()))
            count += len(families)
            last_id = batch[-1].id
        return count

    def search(self, query: str, *, limit: int = 20) -> list[Product]:
        normalized_query = product_name_query(query).strip().lower()
        if not normalized_query:
            return []
        tokens = re.findall(r"[a-z0-9][a-z0-9._+-]*", normalized_query)
        if not tokens:
            return []
        # This exact expression matches the partial GIN index in the migration.
        search_text = func.lower(
            Product.vendor + " " + Product.product_name + " " + Product.cpe_product
        )
        token_match = [search_text.contains(token, autoescape=True) for token in tokens]
        exact_product = func.lower(Product.cpe_product) == normalized_query.replace(" ", "_")
        statement: Select[tuple[Product]] = (
            select(Product)
            .where(Product.is_family.is_(True), Product.cpe_product != "*", or_(
                and_(*token_match), search_text.op("%")(normalized_query),
            ))
            .order_by(case((exact_product, 1), else_=0).desc(),
                      func.similarity(search_text, normalized_query).desc(),
                      Product.vendor, Product.product_name, Product.id)
            .limit(limit)
        )
        return list(self._session.scalars(statement))
