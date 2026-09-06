from collections.abc import Callable
from datetime import datetime
from typing import Any

import httpx

from app.core.time import utc_now
from app.domain.cve import FetchResult, NormalizedCve


class CisaKevFeed:
    source_name = "cisa_kev"

    def __init__(
        self,
        *,
        url: str,
        client: httpx.Client | None = None,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        self._url = url
        self._client = client or httpx.Client(timeout=60.0)
        self._owns_client = client is None
        self._now = now

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def fetch_since(self, since: datetime) -> FetchResult:
        # CISA publishes a full catalog rather than a per-record modification cursor.
        # Reconciliation makes this idempotent and also handles any future removal.
        response = self._client.get(self._url)
        response.raise_for_status()
        payload = response.json()
        records = [normalize_kev_record(record) for record in payload.get("vulnerabilities", [])]
        return FetchResult(records=records, next_cursor=self._now())


def normalize_kev_record(payload: dict[str, Any]) -> NormalizedCve:
    return NormalizedCve(
        cve_id=payload["cveID"],
        source="cisa_kev",
        raw=payload,
        is_kev=True,
    )
