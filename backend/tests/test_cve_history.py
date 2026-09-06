from copy import deepcopy
from datetime import UTC, datetime
from unittest.mock import Mock

from app.domain.cve import NormalizedCve
from app.domain.cve_history import aggregate_cve_sources, meaningful_changes
from app.models.cve import Cve, CveChange
from app.repositories.sqlalchemy_cve_repository import SqlAlchemyCveRepository
from app.services.cve_projection import backfill_cve_projections


def _nvd(score: float = 8.0) -> dict:
    return {
        "cve": {
            "id": "CVE-2026-1234",
            "lastModified": "2026-09-05T00:00:00Z",
            "descriptions": [{"lang": "en", "value": "NVD description"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]},
            "references": [{"url": "https://example.com/fix"}],
            "weaknesses": [{"description": [{"value": "CWE-79"}]}],
        }
    }


def test_merge_prefers_mitre_per_version_and_preserves_nvd_fallback() -> None:
    nvd = _nvd()
    nvd["cve"]["metrics"]["cvssMetricV2"] = [{"cvssData": {"baseScore": 5.0}}]
    mitre = {
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "CNA description"}],
                "metrics": [{"cvssV3_1": {"baseScore": 9.8, "vectorString": "CVSS:3.1/example"}}],
                "references": [
                    {"url": "https://example.com/advisory"},
                    {"url": "https://example.com/fix"},
                ],
                "problemTypes": [{"descriptions": [{"cweId": "CWE-89"}]}],
            }
        }
    }
    sources = {"nvd": nvd, "mitre": mitre}
    original = deepcopy(sources)

    projection = aggregate_cve_sources(sources)

    assert projection["description"] == "CNA description"
    assert projection["cvss_score"] == 9.8
    assert projection["cvss"]["2.0"] == {"score": 5.0, "vector": None, "source": "nvd"}
    assert projection["cvss"]["3.1"]["source"] == "mitre"
    assert projection["references"] == ["https://example.com/advisory", "https://example.com/fix"]
    assert projection["weaknesses"] == ["CWE-79", "CWE-89"]
    assert sources == original


def test_metadata_reorder_and_provenance_only_changes_do_not_create_events() -> None:
    nvd = _nvd()
    nvd["cve"]["references"].append({"url": "https://example.com/advisory"})
    previous = aggregate_cve_sources({"nvd": nvd})
    nvd["cve"]["lastModified"] = "2026-09-06T00:00:00Z"
    nvd["cve"]["references"].reverse()
    current = aggregate_cve_sources({"nvd": nvd})
    current["cvss"]["3.1"]["source"] = "mitre"
    current["description_source"] = "mitre"
    assert meaningful_changes(previous, current) == {}


def test_version_range_correction_is_a_meaningful_change() -> None:
    nvd = _nvd()
    criterion = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
        "versionEndExcluding": "3.0",
    }
    nvd["cve"]["configurations"] = [{"nodes": [{"cpeMatch": [criterion]}]}]
    before = aggregate_cve_sources({"nvd": nvd})
    criterion["versionEndExcluding"] = "2.5"
    after = aggregate_cve_sources({"nvd": nvd})
    assert "affected" in meaningful_changes(before, after)
    assert before["products"] == [{"vendor": "acme", "product": "widget"}]


def test_replaying_identical_record_has_no_history_or_notification_side_effects() -> None:
    cve = Cve(
        id=1, cve_id="CVE-2026-1234", source_json={"nvd": _nvd()}, cvss_score=8.0, is_kev=False
    )
    session = Mock()
    session.scalar.return_value = cve
    repository = SqlAlchemyCveRepository(session)

    repository.upsert_cve(NormalizedCve(cve.cve_id, "nvd", _nvd(), cvss_score=8.0))

    session.add.assert_not_called()
    session.execute.assert_not_called()


def test_changed_record_captures_before_after_once_and_keeps_other_raw_sources() -> None:
    cve = Cve(
        id=1,
        cve_id="CVE-2026-1234",
        source_json={"nvd": _nvd(), "epss": {"epss": "0.7"}},
        cvss_score=8.0,
        epss_score=0.7,
        is_kev=False,
    )
    session = Mock()
    session.scalar.return_value = cve
    repository = SqlAlchemyCveRepository(session)
    record = NormalizedCve(cve.cve_id, "nvd", _nvd(9.8), cvss_score=9.8)

    repository.upsert_cve(record)
    repository.upsert_cve(record)

    changes = [call.args[0] for call in session.add.call_args_list]
    assert len(changes) == 1
    assert isinstance(changes[0], CveChange)
    assert changes[0].changes["cvss_score"] == {"old": 8.0, "new": 9.8}
    assert cve.source_json["epss"] == {"epss": "0.7"}
    assert cve.epss_score == 0.7
    session.execute.assert_called_once()


def test_older_source_record_cannot_overwrite_newer_source_or_reopen_alerts() -> None:
    cve = Cve(
        id=1, cve_id="CVE-2026-1234", source_json={"nvd": _nvd()}, cvss_score=8.0, is_kev=False
    )
    session = Mock()
    session.scalar.return_value = cve
    accepted = SqlAlchemyCveRepository(session).upsert_cve(
        NormalizedCve(
            cve.cve_id,
            "nvd",
            _nvd(5),
            cvss_score=5,
            last_modified_at=datetime(2026, 9, 4, tzinfo=UTC),
        )
    )
    assert accepted is False
    assert cve.cvss_score == 8.0
    session.add.assert_not_called()
    session.execute.assert_not_called()


def test_backfill_initializes_projection_without_fabricating_history_or_resending_email() -> None:
    cve = Cve(
        id=7,
        cve_id="CVE-2026-1234",
        source_json={"nvd": _nvd()},
        normalized_json={},
        cvss_score=8,
        is_kev=False,
    )
    session = Mock()
    session.scalars.return_value.all.side_effect = [[cve], []]
    assert backfill_cve_projections(session) == 1
    assert cve.normalized_json["description"] == "NVD description"
    session.add.assert_not_called()
    session.execute.assert_not_called()
