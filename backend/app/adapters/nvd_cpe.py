import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any

import httpx

from app.adapters.nvd import NVD_MAX_MODIFIED_WINDOW, NvdRateLimiter, _format_nvd_timestamp
from app.core.time import utc_now
from app.domain.cpe import Cpe23, InvalidCpe
from app.domain.product import CatalogFetchResult, CatalogPage, CatalogProduct, product_name_query

NVD_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


class NvdCpeDictionaryFeed:
    source_name = "nvd_cpe_dictionary"

    def __init__(
        self,
        *,
        api_key: str | None,
        results_per_page: int,
        request_interval_seconds: float,
        client: httpx.Client | None = None,
        now: Callable[[], datetime] = utc_now,
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = 6,
    ) -> None:
        self._api_key = api_key
        self._results_per_page = results_per_page
        self._client = client or httpx.Client(timeout=60.0)
        self._owns_client = client is None
        self._rate_limiter = NvdRateLimiter(request_interval_seconds)
        self._now = now
        self._sleep = sleep
        self._max_attempts = max_attempts

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def fetch_since(self, since: datetime) -> CatalogFetchResult:
        if since.tzinfo is None:
            raise ValueError("NVD CPE cursor must be timezone-aware")
        end = self._now().astimezone(UTC)
        products: list[CatalogProduct] = []
        for page in self.iter_pages(since=since, until=end):
            products.extend(page.products)
        return CatalogFetchResult(products=products, next_cursor=end)

    def iter_pages(
        self, *, since: datetime | None = None, start_index: int = 0,
        until: datetime | None = None,
    ) -> Iterator[CatalogPage]:
        """Full bootstrap has no date filter; incremental windows never exceed 120 days.

        Consume and commit each yielded page before requesting another. A full import
        resumes at its committed offset; incremental callers advance the time cursor
        only after a complete window, safely replaying any interrupted window.
        """
        if start_index < 0:
            raise ValueError("start_index must be non-negative")
        end = until or self._now()
        if end.tzinfo is None or (since is not None and since.tzinfo is None):
            raise ValueError("NVD CPE cursors must be timezone-aware")
        end = end.astimezone(UTC)
        if since is None:
            yield from self._iter_window(None, end, start_index)
            return
        start = since.astimezone(UTC)
        while start < end:
            window_end = min(start + NVD_MAX_MODIFIED_WINDOW, end)
            yield from self._iter_window(start, window_end, start_index)
            start, start_index = window_end, 0

    def search_products(self, query: str, *, max_pages: int = 3) -> list[CatalogProduct]:
        """Bounded official dictionary lookup while the background bootstrap runs."""
        keyword = product_name_query(query)
        if not keyword or max_pages < 1:
            return []
        products: list[CatalogProduct] = []
        for index, page in enumerate(self._iter_window(
            None, self._now().astimezone(UTC), 0, keyword=keyword
        )):
            products.extend(page.products)
            if index + 1 >= max_pages:
                break
        return products

    def _iter_window(
        self, start: datetime | None, end: datetime, start_index: int,
        *, keyword: str | None = None,
    ) -> Iterator[CatalogPage]:
        while True:
            params: dict[str, str | int] = {
                "startIndex": start_index,
                "resultsPerPage": self._results_per_page,
            }
            if start is not None:
                params.update(lastModStartDate=_format_nvd_timestamp(start),
                              lastModEndDate=_format_nvd_timestamp(end))
            if keyword:
                params["keywordSearch"] = keyword
            payload = self._request(params)
            raw_products = payload.get("products", [])
            total = int(payload["totalResults"])
            if not raw_products and start_index < total:
                raise ValueError("NVD returned an empty page before the end of the dictionary")
            products = [
                normalized
                for product in raw_products
                if (normalized := normalize_nvd_cpe_product(product)) is not None
            ]
            start_index += len(raw_products)
            complete = start_index >= total
            yield CatalogPage(products, start_index, total, end, complete)
            if complete:
                break

    def _request(self, params: dict[str, str | int]) -> dict[str, Any]:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        for attempt in range(self._max_attempts):
            self._rate_limiter.wait()
            try:
                response = self._client.get(NVD_CPE_API_URL, params=params, headers=headers)
                if response.status_code in {429, 500, 502, 503, 504}:
                    response.raise_for_status()
                response.raise_for_status()
                return response.json()
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code not in {
                    429, 500, 502, 503, 504,
                }:
                    raise
                if attempt + 1 == self._max_attempts:
                    raise
                retry_after = (
                    exc.response.headers.get("Retry-After", "")
                    if isinstance(exc, httpx.HTTPStatusError) else ""
                )
                delay = float(retry_after) if retry_after.isdigit() else min(2 ** attempt, 60)
                self._sleep(min(max(delay, 1), 120))
        raise RuntimeError("NVD request attempts exhausted")


def normalize_nvd_cpe_product(payload: dict[str, Any]) -> CatalogProduct | None:
    cpe_data = payload["cpe"]
    if cpe_data.get("deprecated", False):
        return None
    try:
        cpe = Cpe23.parse(cpe_data["cpeName"])
    except InvalidCpe:
        return None
    title = _english_title(cpe_data.get("titles", []))
    product_name = title or cpe.product.replace("_", " ").replace("-", " ").title()
    return CatalogProduct(
        part=cpe.part,
        vendor=cpe.vendor,
        product_name=product_name,
        cpe_product=cpe.product,
        cpe_version=cpe.version,
        cpe_string=cpe_data["cpeName"],
    )


def _english_title(titles: list[dict[str, str]]) -> str | None:
    for title in titles:
        if title.get("lang", "").lower().startswith("en") and title.get("title"):
            return title["title"]
    return titles[0].get("title") if titles else None
