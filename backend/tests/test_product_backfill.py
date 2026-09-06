from unittest.mock import Mock

from app.domain.cve import NormalizedCve
from app.services.product_backfill import _match_historical_record


def test_older_history_response_matches_current_stored_applicability():
    repository, matcher = Mock(), Mock()
    repository.upsert_cve.return_value = False
    repository.get_cve_source_payload.return_value = {"cve": {"configurations": []}}
    record = NormalizedCve(cve_id="CVE-2026-1234", source="nvd", raw={"old": True})
    _match_historical_record(repository, matcher, record)
    matched = matcher.match_record.call_args.args[0]
    assert matched.cve_id == record.cve_id
    assert matched.raw == {"cve": {"configurations": []}}


def test_accepted_history_response_is_matched_once():
    repository, matcher = Mock(), Mock()
    repository.upsert_cve.return_value = True
    record = NormalizedCve(cve_id="CVE-2026-1234", source="nvd", raw={})
    _match_historical_record(repository, matcher, record)
    matcher.match_record.assert_called_once_with(record)
    repository.get_cve_source_payload.assert_not_called()
