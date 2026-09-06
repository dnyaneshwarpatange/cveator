import csv
import gzip
from collections.abc import Callable, Iterator
from datetime import datetime
from io import BytesIO, TextIOWrapper

import httpx

from app.core.time import utc_now
from app.domain.cve import FetchResult, NormalizedCve


class EpssCsvFeed:
    """Imports FIRST's daily bulk score file; the lookup API is not used for bulk work."""

    source_name = "epss"

    def __init__(
        self,
        *,
        url: str,
        client: httpx.Client | None = None,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        self._url = url
        self._client = client or httpx.Client(timeout=120.0, follow_redirects=True)
        self._owns_client = client is None
        self._now = now

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def fetch_since(self, since: datetime) -> FetchResult:
        # This stable URL always represents the current daily score set, so a full replacement
        # is both more efficient and more accurate than issuing one lookup request per CVE.
        return FetchResult(records=list(self.iter_records()), next_cursor=self._now())

    def iter_records(self) -> Iterator[NormalizedCve]:
        response = self._client.get(self._url)
        response.raise_for_status()
        yield from parse_epss_csv(response.content)


def parse_epss_csv(compressed_csv: bytes) -> Iterator[NormalizedCve]:
    with gzip.GzipFile(fileobj=BytesIO(compressed_csv)) as decompressed:
        text = TextIOWrapper(decompressed, encoding="utf-8")
        score_date = None

        def data_lines():
            nonlocal score_date
            for line in text:
                if line.startswith("#"):
                    for field in line[1:].strip().split(","):
                        key, _, value = field.partition(":")
                        if key.strip() == "score_date":
                            score_date = value.strip()[:10]
                    continue
                yield line

        lines = data_lines()
        for row in csv.DictReader(lines):
            cve_id = row["cve"]
            score = float(row["epss"])
            if not 0 <= score <= 1:
                raise ValueError("EPSS probability must be between zero and one")
            yield NormalizedCve(
                cve_id=cve_id,
                source="epss",
                raw={
                    "cve": cve_id,
                    "epss": row["epss"],
                    "percentile": row.get("percentile"),
                    "date": row.get("date") or score_date,
                },
                epss_score=score,
            )
