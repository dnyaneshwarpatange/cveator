from datetime import datetime
from typing import Protocol

from app.domain.cve import NormalizedCve


class CveRepository(Protocol):
    def get_cursor(self, source: str) -> datetime | None: ...

    def save_cursor(self, source: str, high_watermark: datetime) -> None: ...

    def upsert_cve(self, record: NormalizedCve) -> bool | None: ...

    def reconcile_kev(self, active_cve_ids: set[str]) -> None: ...
