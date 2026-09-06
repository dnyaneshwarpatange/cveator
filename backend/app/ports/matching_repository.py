from typing import Protocol

from app.domain.cve import ProductCandidate


class MatchingRepository(Protocol):
    def find_product_candidates(
        self, *, part: str, vendor: str, product: str
    ) -> list[ProductCandidate]: ...

    def find_family_candidates(self, *, vendor: str, product: str) -> list[ProductCandidate]: ...

    def get_cve_source_payload(self, cve_id: str, source: str) -> dict | None: ...

    def create_cve_product_matches(self, cve_id: str, product_ids: set[int]) -> int: ...

    def reconcile_cve_product_matches(self, cve_id: str, product_ids: set[int]) -> int: ...
