import re
from dataclasses import dataclass
from datetime import datetime


def product_name_query(query: str) -> str:
    """Search a named family; a typed patch version never means a different release."""
    return " ".join(
        token for token in query.strip().split()
        if not re.fullmatch(r"[vV]?\d+(?:[._-]\d+)+(?:[A-Za-z0-9-]+)?", token)
    )


@dataclass(frozen=True, slots=True)
class CatalogProduct:
    part: str
    vendor: str
    product_name: str
    cpe_product: str
    cpe_version: str
    cpe_string: str


@dataclass(frozen=True, slots=True)
class CatalogFetchResult:
    products: list[CatalogProduct]
    next_cursor: datetime


@dataclass(frozen=True, slots=True)
class CatalogPage:
    products: list[CatalogProduct]
    next_start_index: int
    total_results: int
    window_end: datetime
    complete: bool
