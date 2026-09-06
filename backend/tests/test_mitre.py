from datetime import UTC, datetime

import httpx

from app.adapters.mitre import MitreCveListFeed, normalize_mitre_record


def test_mitre_feed_reads_delta_log_and_deduplicates_cves() -> None:
    first_url = "https://records.example/CVE-2026-0001.json"
    latest_url = "https://records.example/CVE-2026-0001-latest.json"
    delta_log_url = "https://records.example/deltaLog.json"
    delta = [
        {
            "fetchTime": "2026-01-01T01:00:00.000Z",
            "new": [
                {"cveId": "CVE-2026-ignored", "githubLink": "https://records.example/old.json"}
            ],
        },
        {
            "fetchTime": "2026-01-02T01:00:00.000Z",
            "new": [{"cveId": "CVE-2026-0001", "githubLink": first_url}],
        },
        {
            "fetchTime": "2026-01-02T02:00:00.000Z",
            "updated": [{"cveId": "CVE-2026-0001", "githubLink": latest_url}],
        },
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == delta_log_url:
            return httpx.Response(200, json=delta)
        if str(request.url) == latest_url:
            return httpx.Response(200, json=_mitre_record("CVE-2026-0001"))
        raise AssertionError(f"Unexpected upstream URL: {request.url}")

    feed = MitreCveListFeed(
        delta_log_url=delta_log_url,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        now=lambda: datetime(2026, 1, 3, tzinfo=UTC),
    )

    result = feed.fetch_since(datetime(2026, 1, 2, tzinfo=UTC))

    assert [record.cve_id for record in result.records] == ["CVE-2026-0001"]
    assert result.records[0].cvss_score == 8.8
    assert result.next_cursor == datetime(2026, 1, 2, 2, tzinfo=UTC)


def test_mitre_normalizer_reads_adp_metrics_when_cna_has_none() -> None:
    payload = _mitre_record("CVE-2026-0002")
    payload["containers"]["cna"] = {}

    record = normalize_mitre_record(payload)

    assert record.cvss_score == 8.8
    assert record.last_modified_at == datetime(2026, 1, 2, tzinfo=UTC)


def _mitre_record(cve_id: str) -> dict[str, object]:
    return {
        "cveMetadata": {
            "cveId": cve_id,
            "datePublished": "2026-01-01T00:00:00.000Z",
            "dateUpdated": "2026-01-02T00:00:00.000Z",
        },
        "containers": {
            "cna": {},
            "adp": [{"metrics": [{"cvssV3_1": {"baseScore": 8.8}}]}],
        },
    }
