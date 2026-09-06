import gzip
import hashlib
import json
from datetime import UTC, datetime
from unittest.mock import Mock

import httpx
import pytest
from sqlalchemy.dialects import postgresql

from app.adapters.nvd_bulk import InvalidNvdFeed, NvdYearlyFeed
from app.domain.cve import NormalizedCve
from app.models.catalog_import import CatalogImport
from app.models.cve import Cve
from app.repositories.sqlalchemy_cve_repository import SqlAlchemyCveRepository
from app.scripts.bootstrap_cves import _finalize_baseline, run_bootstrap
from app.services.cve_bulk import import_cve_batch


def test_yearly_feed_verifies_uncompressed_digest_and_streams_real_shape() -> None:
    payload = json.dumps(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-1234",
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.8}},
                            ]
                        },
                    }
                }
            ]
        }
    ).encode()
    checksum = hashlib.sha256(payload).hexdigest().upper()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "nvd.nist.gov"
        assert "apikey" not in request.headers
        assert "authorization" not in request.headers
        if request.url.path.endswith(".meta"):
            return httpx.Response(200, text=f"lastModifiedDate:2026-09-05\nsha256:{checksum}")
        assert request.url.path.endswith("nvdcve-2.0-2026.json.gz")
        return httpx.Response(200, content=gzip.compress(payload))

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with NvdYearlyFeed(client=client).records(2026) as records:
            result = list(records)
    assert len(result) == 1
    assert result[0].cve_id == "CVE-2026-1234"
    assert result[0].cvss_score == 9.8
    assert isinstance(
        result[0].raw["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"], float
    )


def test_invalid_checksum_yields_no_records() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(".meta"):
            return httpx.Response(200, text="sha256:" + "0" * 64)
        return httpx.Response(200, content=gzip.compress(b'{"vulnerabilities": []}'))

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(InvalidNvdFeed, match="checksum mismatch"):
            with NvdYearlyFeed(client=client).records(2026):
                pytest.fail("Unverified records must never be exposed")


def test_batch_replay_skips_identical_existing_records_without_individual_queries() -> None:
    raw = {"cve": {"id": "CVE-2026-1234"}}
    session = Mock()
    session.execute.return_value.all.return_value = [
        ("CVE-2026-1234", {"nvd": raw, "epss": {"epss": "0.5"}})
    ]
    assert import_cve_batch(session, [NormalizedCve("CVE-2026-1234", "nvd", raw)]) == 1
    session.execute.assert_called_once()
    session.scalar.assert_not_called()
    session.add.assert_not_called()


def test_new_batch_inserts_projection_without_artificial_history() -> None:
    session = Mock()
    session.execute.return_value.all.return_value = []
    session.scalars.return_value = ["CVE-2026-1234"]
    record = NormalizedCve("CVE-2026-1234", "nvd", {"cve": {"id": "CVE-2026-1234"}})
    assert import_cve_batch(session, [record]) == 1
    statement = session.scalars.call_args.args[0]
    compiled = statement.compile(dialect=postgresql.dialect())
    assert "ON CONFLICT" in str(compiled)
    assert any(
        isinstance(value, dict) and "references" in value for value in compiled.params.values()
    )
    session.add.assert_not_called()


def test_baseline_update_keeps_delivery_and_user_status_while_invalidating_summary() -> None:
    cve = Cve(id=1, cve_id="CVE-2026-1234", source_json={"nvd": {}}, cvss_score=5, is_kev=False)
    session = Mock()
    session.scalar.return_value = cve
    SqlAlchemyCveRepository(session, notify_changes=False).upsert_cve(
        NormalizedCve(
            cve.cve_id,
            "nvd",
            {"cve": {"id": cve.cve_id}},
            cvss_score=9,
        )
    )
    sql = str(session.execute.call_args.args[0].compile(dialect=postgresql.dialect()))
    assert "plain_summary" in sql
    assert "sent_at" not in sql
    assert "status=" not in sql


def test_incomplete_global_baseline_does_not_advance_cursor() -> None:
    session = Mock()
    session.scalars.return_value = [
        CatalogImport(
            source="nvd_cves_2026",
            status="complete",
            total_results=40000,
            started_at=datetime(2026, 9, 5, tzinfo=UTC),
        )
    ]
    assert _finalize_baseline(session, {"nvd_cves_2026", "nvd_cves_2025"}) is False
    session.add.assert_not_called()
    session.scalar.assert_not_called()


def test_completed_baseline_rerun_does_not_rewind_incremental_cursor() -> None:
    session = Mock()
    session.scalars.return_value = [
        CatalogImport(
            source="nvd_cves_2026",
            status="complete",
            total_results=40000,
            started_at=datetime(2026, 9, 5, tzinfo=UTC),
        )
    ]
    session.get.return_value = CatalogImport(source="nvd_cves", status="complete")
    assert _finalize_baseline(session, {"nvd_cves_2026"}) is True
    session.add.assert_not_called()
    session.scalar.assert_not_called()


def test_first_global_completion_sets_marker_and_earliest_catchup_cursor_together() -> None:
    start = datetime(2026, 9, 5, tzinfo=UTC)
    session = Mock()
    session.scalars.return_value = [
        CatalogImport(
            source="nvd_cves_2026", status="complete", total_results=40000, started_at=start
        ),
        CatalogImport(
            source="nvd_cves_2025",
            status="complete",
            total_results=35000,
            started_at=datetime(2026, 9, 6, tzinfo=UTC),
        ),
    ]
    session.get.return_value = None
    session.scalar.return_value = None
    assert _finalize_baseline(session, {"nvd_cves_2026", "nvd_cves_2025"}) is True
    added = [call.args[0] for call in session.add.call_args_list]
    marker = next(item for item in added if isinstance(item, CatalogImport))
    cursor = next(item for item in added if not isinstance(item, CatalogImport))
    assert marker.source == "nvd_cves" and marker.status == "complete"
    assert marker.total_results == 75000
    assert cursor.source == "nvd" and cursor.high_watermark == start
    session.commit.assert_not_called()  # Caller commits both mutations atomically.


def test_bulk_merge_keeps_other_sources_and_enrichment() -> None:
    raw = {
        "cve": {
            "id": "CVE-2026-1234",
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 9.8}},
                ]
            },
        }
    }
    cve = Cve(
        id=1,
        cve_id="CVE-2026-1234",
        source_json={
            "nvd": {},
            "mitre": {"containers": {}},
            "epss": {"epss": "0.5"},
        },
        cvss_score=5,
        epss_score=0.5,
        is_kev=True,
    )
    session = Mock()
    session.execute.return_value.all.return_value = [(cve.cve_id, cve.source_json)]
    session.scalar.return_value = cve
    import_cve_batch(session, [NormalizedCve(cve.cve_id, "nvd", raw, cvss_score=9.8)])
    assert cve.source_json["mitre"] == {"containers": {}}
    assert cve.source_json["epss"] == {"epss": "0.5"}
    assert cve.source_json["nvd"] == raw
    assert cve.epss_score == 0.5 and cve.is_kev is True
    assert cve.cvss_score == 9.8


def test_callable_rejects_unbounded_batch_sizes_before_initializing_database() -> None:
    with pytest.raises(ValueError, match="batch-size"):
        run_bootstrap(batch_size=50000)


@pytest.mark.parametrize("year", [1999, 2000, 2001])
def test_nonexistent_early_year_feeds_are_not_requested(year: int) -> None:
    with pytest.raises(ValueError, match="feed years"):
        run_bootstrap(years=[year])
