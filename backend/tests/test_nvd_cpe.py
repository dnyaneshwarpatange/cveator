from datetime import UTC, datetime

import httpx

from app.adapters.nvd_cpe import NvdCpeDictionaryFeed, normalize_nvd_cpe_product


def test_nvd_cpe_feed_paginates_and_normalizes_catalog_entries() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["startIndex"] == "0"
        return httpx.Response(
            200,
            json={
                "totalResults": 1,
                "products": [
                    {
                        "cpe": {
                            "cpeName": "cpe:2.3:a:acme:widget:2.5:*:*:*:*:*:*:*",
                            "deprecated": False,
                            "titles": [{"lang": "en", "title": "Acme Widget 2.5"}],
                        }
                    }
                ],
            },
        )

    now = datetime(2026, 1, 2, tzinfo=UTC)
    feed = NvdCpeDictionaryFeed(
        api_key="test-key",
        results_per_page=10_000,
        request_interval_seconds=0,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        now=lambda: now,
    )

    result = feed.fetch_since(datetime(2026, 1, 1, tzinfo=UTC))

    assert result.next_cursor == now
    assert result.products[0].vendor == "acme"
    assert result.products[0].product_name == "Acme Widget 2.5"
    assert result.products[0].cpe_version == "2.5"


def test_nvd_cpe_normalizer_skips_deprecated_entries() -> None:
    product = normalize_nvd_cpe_product(
        {
            "cpe": {
                "cpeName": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
                "deprecated": True,
            }
        }
    )

    assert product is None
