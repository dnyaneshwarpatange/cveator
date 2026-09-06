from datetime import UTC, datetime

import httpx

from app.adapters.cisa_kev import CisaKevFeed


def test_cisa_kev_feed_normalizes_full_catalog() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://kev.example/catalog.json"
        return httpx.Response(
            200,
            json={
                "catalogVersion": "2026.01.01",
                "vulnerabilities": [{"cveID": "CVE-2026-0001", "vendorProject": "Example"}],
            },
        )

    now = datetime(2026, 1, 2, tzinfo=UTC)
    feed = CisaKevFeed(
        url="https://kev.example/catalog.json",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        now=lambda: now,
    )

    result = feed.fetch_since(datetime(2026, 1, 1, tzinfo=UTC))

    assert result.next_cursor == now
    assert result.records[0].cve_id == "CVE-2026-0001"
    assert result.records[0].is_kev is True
