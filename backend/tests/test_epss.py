import gzip
from datetime import UTC, datetime

import httpx
import pytest

from app.adapters.epss import EpssCsvFeed, parse_epss_csv


def test_epss_parser_handles_a_commented_daily_csv() -> None:
    payload = gzip.compress(
        b"#model_version:v5.0,score_date:2026-01-02\n"
        b"cve,epss,percentile\n"
        b"CVE-2026-0001,0.123450000,0.987650000\n"
    )

    records = list(parse_epss_csv(payload))

    assert records[0].cve_id == "CVE-2026-0001"
    assert records[0].epss_score == 0.12345
    assert records[0].raw["percentile"] == "0.987650000"
    assert records[0].raw["date"] == "2026-01-02"


@pytest.mark.parametrize("value", ["NaN", "inf", "-0.1", "1.01"])
def test_epss_parser_rejects_invalid_probabilities(value: str) -> None:
    payload = gzip.compress(f"cve,epss,percentile\nCVE-2026-0001,{value},0.9\n".encode())
    with pytest.raises(ValueError, match="probability"):
        list(parse_epss_csv(payload))


def test_epss_feed_follows_the_bulk_file_contract() -> None:
    payload = gzip.compress(b"cve,epss,percentile\nCVE-2026-0002,0.4,0.9\n")
    now = datetime(2026, 1, 2, tzinfo=UTC)

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://epss.example/current.csv.gz"
        return httpx.Response(200, content=payload)

    feed = EpssCsvFeed(
        url="https://epss.example/current.csv.gz",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        now=lambda: now,
    )

    result = feed.fetch_since(datetime(2026, 1, 1, tzinfo=UTC))

    assert result.next_cursor == now
    assert result.records[0].epss_score == 0.4
