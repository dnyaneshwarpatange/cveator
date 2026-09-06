from unittest.mock import Mock

from app.domain.cve import NormalizedCve, ProductCandidate
from app.services.matching import CveProductMatcher


def source_record(*, vendor="ACME Corp", product="My Tool", versions=None):
    return NormalizedCve(cve_id="CVE-2026-1234", source="mitre", raw={
        "cveMetadata": {"state": "PUBLISHED"},
        "containers": {"cna": {"affected": [{
            "vendor": vendor, "product": product,
            "versions": versions or [{"version": "1.2", "status": "affected"}],
        }]}},
    })


def test_early_cna_data_matches_exact_family_and_vendor_but_not_installed_release() -> None:
    repository = Mock()
    repository.get_cve_source_payload.return_value = None
    repository.find_family_candidates.return_value = [
        ProductCandidate(1, "cpe:2.3:a:acme_corp:my_tool:*:*:*:*:*:*:*:*"),
        ProductCandidate(2, "cpe:2.3:a:acme_corp:my_tool:1.2:*:*:*:*:*:*:*"),
        ProductCandidate(3, "cpe:2.3:*:acme_corp:*:*:*:*:*:*:*:*:*"),
        ProductCandidate(4, "cpe:2.3:a:other:my_tool:*:*:*:*:*:*:*:*"),
    ]
    CveProductMatcher(repository).match_record(source_record())
    repository.find_family_candidates.assert_called_once_with(vendor="acme_corp", product="my_tool")
    repository.reconcile_cve_product_matches.assert_called_once_with("CVE-2026-1234", {1, 3})


def test_cna_update_recalculates_stored_nvd_associations_instead_of_erasing_them() -> None:
    repository = Mock()
    repository.get_cve_source_payload.return_value = {"cve": {"configurations": [{"nodes": [{
        "cpeMatch": [{"vulnerable": True,
                      "criteria": "cpe:2.3:a:acme_corp:my_tool:1.2:*:*:*:*:*:*:*"}],
    }]}]}}
    repository.find_product_candidates.return_value = [
        ProductCandidate(2, "cpe:2.3:a:acme_corp:my_tool:1.2:*:*:*:*:*:*:*"),
    ]
    CveProductMatcher(repository).match_record(source_record(product="Renamed Tool"))
    repository.find_family_candidates.assert_not_called()
    repository.reconcile_cve_product_matches.assert_called_once_with("CVE-2026-1234", {2})


def test_explicit_empty_nvd_applicability_removes_stale_cna_matches() -> None:
    repository = Mock()
    repository.get_cve_source_payload.return_value = {"cve": {"configurations": []}}
    CveProductMatcher(repository).match_record(source_record())
    repository.find_family_candidates.assert_not_called()
    repository.reconcile_cve_product_matches.assert_called_once_with("CVE-2026-1234", set())


def test_awaiting_nvd_enrichment_keeps_cna_family_coverage() -> None:
    repository = Mock()
    record = source_record()
    repository.get_cve_source_payload.return_value = record.raw
    repository.find_family_candidates.return_value = [
        ProductCandidate(1, "cpe:2.3:a:acme_corp:my_tool:*:*:*:*:*:*:*:*"),
    ]
    CveProductMatcher(repository).match_record(NormalizedCve(
        cve_id=record.cve_id, source="nvd", raw={"cve": {"vulnStatus": "Awaiting Analysis"}},
    ))
    repository.reconcile_cve_product_matches.assert_called_once_with(record.cve_id, {1})


def test_unaffected_cna_product_does_not_generate_a_family_match() -> None:
    repository = Mock()
    repository.get_cve_source_payload.return_value = None
    CveProductMatcher(repository).match_record(source_record(
        versions=[{"version": "1.2", "status": "unaffected"}],
    ))
    repository.find_family_candidates.assert_not_called()
    repository.reconcile_cve_product_matches.assert_called_once_with("CVE-2026-1234", set())


def test_rejected_nvd_record_does_not_fall_back_to_stale_cna_data() -> None:
    repository = Mock()
    repository.get_cve_source_payload.return_value = source_record().raw
    CveProductMatcher(repository).match_record(NormalizedCve(
        cve_id="CVE-2026-1234", source="nvd", raw={"cve": {"vulnStatus": "Rejected"}},
    ))
    repository.find_family_candidates.assert_not_called()
    repository.reconcile_cve_product_matches.assert_called_once_with("CVE-2026-1234", set())
