from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WatchlistProduct:
    id: int
    vendor: str
    product_name: str
    version: str
