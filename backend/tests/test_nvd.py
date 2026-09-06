from datetime import UTC, datetime

import httpx

from app.adapters.nvd import NvdCveFeed, normalize_nvd_vulnerability


def test_nvd_feed_paginates_and_normalizes_records() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        start_index = request.url.params["startIndex"]
        if start_index == "0":
            payload = {
                "totalResults": 2,
                "vulnerabilities": [_nvd_payload("CVE-2026-0001", 9.8)],
            }
        else:
            payload = {
                "totalResults": 2,
                "vulnerabilities": [_nvd_payload("CVE-2026-0002", 7.5)],
            }
        return httpx.Response(200, json=payload)

    now = datetime(2026, 1, 2, tzinfo=UTC)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    feed = NvdCveFeed(
        api_key="test-key",
        results_per_page=1,
        request_interval_seconds=0,
        client=client,
        now=lambda: now,
    )

    result = feed.fetch_since(datetime(2026, 1, 1, tzinfo=UTC))

    assert [record.cve_id for record in result.records] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert [record.cvss_score for record in result.records] == [9.8, 7.5]
    assert result.next_cursor == now
    assert len(requests) == 2
    assert requests[0].headers["apiKey"] == "test-key"
    assert requests[0].url.params["lastModStartDate"].endswith("+00:00")
    assert "UTC" not in requests[0].url.params["lastModStartDate"]


def test_nvd_normalizer_uses_newest_available_cvss_metric() -> None:
    payload = _nvd_payload("CVE-2026-0003", 8.1)
    payload["cve"]["published"] = "2026-01-01T00:00:00.000"
    payload["cve"]["metrics"] = {
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}],
    }

    record = normalize_nvd_vulnerability(payload)

    assert record.cvss_score == 8.1
    assert record.published_at == datetime(2026, 1, 1, tzinfo=UTC)


def _nvd_payload(cve_id: str, score: float) -> dict[str, object]:
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-01-01T00:00:00.000Z",
            "lastModified": "2026-01-01T01:00:00.000Z",
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]},
        }
    }
