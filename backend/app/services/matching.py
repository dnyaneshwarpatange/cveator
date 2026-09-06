import re

from app.domain.cpe import (
    Cpe23,
    InvalidCpe,
    extract_vulnerable_cpe_matches,
    product_matches_cpe_criterion,
)
from app.domain.cve import NormalizedCve
from app.ports.matching_repository import MatchingRepository


class CveProductMatcher:
    """Evaluate current source applicability only for watched products.

    NVD's explicit applicability is authoritative. Before it is available, CNA
    product identities may match all-version families and vendor subscriptions;
    names alone never establish applicability for an installed patch version.
    """

    def __init__(self, repository: MatchingRepository) -> None:
        self._repository = repository

    def match_record(self, record: NormalizedCve) -> int:
        if record.source not in {"nvd", "mitre"}:
            return 0
        nvd = (
            record.raw if record.source == "nvd"
            else self._repository.get_cve_source_payload(record.cve_id, "nvd")
        )
        if nvd is not None and nvd.get("cve", nvd).get("vulnStatus", "").lower() == "rejected":
            matching_product_ids = set()
        elif nvd is not None and "configurations" in nvd.get("cve", nvd):
            matching_product_ids = self._nvd_matches(nvd)
        else:
            mitre = (
                record.raw if record.source == "mitre"
                else self._repository.get_cve_source_payload(record.cve_id, "mitre")
            )
            matching_product_ids = self._mitre_matches(mitre or {})
        # Recalculate from current source records, not event order: a later CNA
        # enrichment cannot erase or broaden NVD's already published applicability.
        return self._repository.reconcile_cve_product_matches(record.cve_id, matching_product_ids)

    def _nvd_matches(self, raw: dict) -> set[int]:
        matching_product_ids: set[int] = set()
        if raw.get("cve", raw).get("vulnStatus", "").lower() == "rejected":
            return matching_product_ids
        for criterion in extract_vulnerable_cpe_matches(raw):
            try:
                cpe = Cpe23.parse(criterion["criteria"])
            except InvalidCpe:
                continue
            candidates = self._repository.find_product_candidates(
                part=cpe.part, vendor=cpe.vendor, product=cpe.product
            )
            for candidate in candidates:
                try:
                    product_cpe = Cpe23.parse(candidate.cpe_string)
                except InvalidCpe:
                    continue
                if product_matches_cpe_criterion(product_cpe, criterion):
                    matching_product_ids.add(candidate.id)
        return matching_product_ids

    def _mitre_matches(self, raw: dict) -> set[int]:
        if raw.get("cveMetadata", {}).get("state", "").upper() == "REJECTED":
            return set()
        containers = raw.get("containers", {})
        identities: set[tuple[str, str]] = set()
        for container in [containers.get("cna", {}), *containers.get("adp", [])]:
            for affected in container.get("affected", []):
                versions = affected.get("versions", [])
                if (affected.get("defaultStatus") != "affected"
                        and (versions or affected.get("defaultStatus") == "unaffected")
                        and not any(version.get("status") == "affected" for version in versions)):
                    continue
                vendor = _canonical_identity(affected.get("vendor", ""))
                product = _canonical_identity(affected.get("product", ""))
                if vendor and vendor not in {"n/a", "na", "unknown", "*"}:
                    identities.add((vendor, product))
                # Structured CPE identity is stronger than a display name. We still
                # use family scope until explicit applicability is available.
                for value in affected.get("cpes", []):
                    try:
                        cpe = Cpe23.parse(value)
                    except (InvalidCpe, TypeError):
                        continue
                    if cpe.vendor not in {"*", "-"}:
                        identities.add((
                            _canonical_identity(cpe.vendor), _canonical_identity(cpe.product)
                        ))
        matches: set[int] = set()
        for vendor, product in identities:
            for candidate in self._repository.find_family_candidates(
                vendor=vendor, product=product,
            ):
                try:
                    cpe = Cpe23.parse(candidate.cpe_string)
                except InvalidCpe:
                    continue
                if (cpe.version == "*" and _canonical_identity(cpe.vendor) == vendor
                        and (cpe.product == "*" or _canonical_identity(cpe.product) == product)):
                    matches.add(candidate.id)
        return matches


def _canonical_identity(value: str) -> str:
    return re.sub(r"[\s_]+", "_", value.strip().casefold())
