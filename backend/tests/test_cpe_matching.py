from app.domain.cpe import Cpe23, extract_vulnerable_cpe_matches, product_matches_cpe_criterion
from app.domain.cve import NormalizedCve, ProductCandidate
from app.services.matching import CveProductMatcher


def test_cpe_match_honors_inclusive_and_exclusive_version_bounds() -> None:
    criterion = {
        "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "2.0",
        "versionEndExcluding": "3.0",
    }

    assert product_matches_cpe_criterion(
        Cpe23.parse("cpe:2.3:a:acme:widget:2.10:*:*:*:*:*:*:*"), criterion
    )
    assert not product_matches_cpe_criterion(
        Cpe23.parse("cpe:2.3:a:acme:widget:3.0:*:*:*:*:*:*:*"), criterion
    )
    assert not product_matches_cpe_criterion(
        Cpe23.parse("cpe:2.3:a:other:widget:2.5:*:*:*:*:*:*:*"), criterion
    )


def test_cpe_extractor_walks_nested_nvd_configuration_nodes() -> None:
    raw = {
        "cve": {
            "configurations": [
                {
                    "nodes": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                                        },
                                        {
                                            "vulnerable": False,
                                            "criteria": "cpe:2.3:a:acme:dependency:*:*:*:*:*:*:*:*",
                                        },
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    }

    matches = extract_vulnerable_cpe_matches(raw)

    assert [match["criteria"] for match in matches] == ["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"]


def test_matcher_creates_only_matching_product_relations() -> None:
    repository = FakeMatchingRepository(
        candidates=[
            ProductCandidate(1, "cpe:2.3:a:acme:widget:2.5:*:*:*:*:*:*:*"),
            ProductCandidate(2, "cpe:2.3:a:acme:widget:3.0:*:*:*:*:*:*:*"),
        ]
    )
    matcher = CveProductMatcher(repository)
    record = NormalizedCve(
        cve_id="CVE-2026-0001",
        source="nvd",
        raw={
            "cve": {
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "2.0",
                                        "versionEndExcluding": "3.0",
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        },
    )

    created = matcher.match_record(record)

    assert created == 1
    assert repository.created == [("CVE-2026-0001", {1})]


class FakeMatchingRepository:
    def __init__(self, *, candidates: list[ProductCandidate]) -> None:
        self._candidates = candidates
        self.created: list[tuple[str, set[int]]] = []

    def find_product_candidates(
        self, *, part: str, vendor: str, product: str
    ) -> list[ProductCandidate]:
        assert (part, vendor, product) == ("a", "acme", "widget")
        return self._candidates

    def reconcile_cve_product_matches(self, cve_id: str, product_ids: set[int]) -> int:
        self.created.append((cve_id, product_ids))
        return len(product_ids)


def test_empty_updated_configuration_reconciles_previously_matched_products() -> None:
    repository = FakeMatchingRepository(candidates=[])
    result = CveProductMatcher(repository).match_record(
        NormalizedCve(
            cve_id="CVE-2026-0001",
            source="nvd",
            raw={"cve": {"configurations": []}},
        )
    )
    assert result == 0
    assert repository.created == [("CVE-2026-0001", set())]
