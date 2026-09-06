import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from app.core.time import parse_upstream_datetime, utc_now
from app.domain.cve import FetchResult, NormalizedCve

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_MAX_MODIFIED_WINDOW = timedelta(days=120)


class NvdRateLimiter:
    """Simple process-local spacing for the documented NVD request quotas."""

    def __init__(
        self,
        minimum_interval_seconds: float,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.minimum_interval_seconds = minimum_interval_seconds
        self._monotonic = monotonic
        self._sleep = sleep
        self._last_request_at: float | None = None

    def wait(self) -> None:
        now = self._monotonic()
        if self._last_request_at is not None:
            remaining = self.minimum_interval_seconds - (now - self._last_request_at)
            if remaining > 0:
                self._sleep(remaining)
        self._last_request_at = self._monotonic()


class NvdCveFeed:
    source_name = "nvd"

    def __init__(
        self,
        *,
        api_key: str | None,
        results_per_page: int,
        request_interval_seconds: float,
        client: httpx.Client | None = None,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        self._api_key = api_key
        self._results_per_page = results_per_page
        self._client = client or httpx.Client(timeout=60.0)
        self._owns_client = client is None
        self._rate_limiter = NvdRateLimiter(request_interval_seconds)
        self._now = now

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def fetch_since(self, since: datetime) -> FetchResult:
        end = self._now().astimezone(UTC)
        if since.tzinfo is None:
            raise ValueError("NVD cursor must be timezone-aware")
        start = since.astimezone(UTC)
        records: list[NormalizedCve] = []
        while start < end:
            window_end = min(start + NVD_MAX_MODIFIED_WINDOW, end)
            records.extend(self._fetch_window(start, window_end))
            start = window_end
        return FetchResult(records=records, next_cursor=end)

    def iter_pages(
        self, since: datetime, *, until: datetime | None = None
    ) -> Iterator[FetchResult]:
        """Commit a page at a time; interrupted windows are safely replayed."""
        if since.tzinfo is None:
            raise ValueError("NVD cursor must be timezone-aware")
        start = since.astimezone(UTC)
        end = (until or self._now()).astimezone(UTC)
        while start < end:
            window_end = min(start + NVD_MAX_MODIFIED_WINDOW, end)
            params = {"lastModStartDate": _format_nvd_timestamp(start),
                      "lastModEndDate": _format_nvd_timestamp(window_end)}
            for records, complete in self._iter_query(params):
                yield FetchResult(records, window_end if complete else start)
            start = window_end

    def iter_product(self, cpe_string: str) -> Iterator[list[NormalizedCve]]:
        """NVD virtual match queries accept wildcard product/vendor subscriptions."""
        for records, _ in self._iter_query({"virtualMatchString": cpe_string}):
            yield records

    def _iter_query(self, query: dict[str, str]) -> Iterator[tuple[list[NormalizedCve], bool]]:
        start = 0
        while True:
            params = {**query, "startIndex": start, "resultsPerPage": self._results_per_page}
            payload = self._request(params)
            raw = payload.get("vulnerabilities", [])
            total = int(payload["totalResults"])
            if not raw and start < total:
                raise ValueError("NVD returned an empty page before the end of the result")
            start += len(raw)
            complete = start >= total
            yield [normalize_nvd_vulnerability(item) for item in raw], complete
            if complete:
                break

    def _request(self, params: dict) -> dict:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        for attempt in range(6):
            self._rate_limiter.wait()
            try:
                response = self._client.get(NVD_CVE_API_URL, params=params, headers=headers)
                response.raise_for_status()
                return response.json()
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code not in {
                    429, 500, 502, 503, 504,
                }:
                    raise
                if attempt == 5:
                    raise
                time.sleep(min(2 ** attempt, 30))
        raise RuntimeError("NVD retry limit exceeded")

    def _fetch_window(self, start: datetime, end: datetime) -> list[NormalizedCve]:
        start_index = 0
        records: list[NormalizedCve] = []
        while True:
            params = {
                "lastModStartDate": _format_nvd_timestamp(start),
                "lastModEndDate": _format_nvd_timestamp(end),
                "startIndex": start_index,
                "resultsPerPage": self._results_per_page,
            }
            headers = {"apiKey": self._api_key} if self._api_key else {}
            self._rate_limiter.wait()
            response = self._client.get(NVD_CVE_API_URL, params=params, headers=headers)
            response.raise_for_status()
            payload = response.json()
            vulnerabilities = payload.get("vulnerabilities", [])
            records.extend(normalize_nvd_vulnerability(item) for item in vulnerabilities)
            start_index += len(vulnerabilities)
            if start_index >= int(payload.get("totalResults", 0)) or not vulnerabilities:
                break
        return records


def _format_nvd_timestamp(value: datetime) -> str:
    value = value.astimezone(UTC)
    # NVD accepts ISO-8601 offsets (the `+` is percent-encoded by the HTTP client).
    # Including the human-readable `UTC` token makes the 2.0 API return 404.
    return value.isoformat(timespec="milliseconds")


def normalize_nvd_vulnerability(payload: dict[str, Any]) -> NormalizedCve:
    cve = payload["cve"]
    return NormalizedCve(
        cve_id=cve["id"],
        source="nvd",
        raw=payload,
        cvss_score=_extract_nvd_cvss_score(cve.get("metrics", {})),
        published_at=parse_upstream_datetime(cve.get("published")),
        last_modified_at=parse_upstream_datetime(cve.get("lastModified")),
    )


def _extract_nvd_cvss_score(metrics: dict[str, Any]) -> float | None:
    # Prefer the newest CVSS version where NVD has supplied one.
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    return None
