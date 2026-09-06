"""Deterministic, source-aware CVE aggregation and meaningful change detection.

Raw upstream records remain the source of truth. This projection contains only
fields that are useful to a person reviewing a vulnerability, not feed metadata.
"""

import json
import re
from typing import Any

from app.domain.cpe import Cpe23, InvalidCpe, extract_vulnerable_cpe_matches

CVSS_VERSIONS = ("4.0", "3.1", "3.0", "2.0")


def aggregate_cve_sources(sources: dict[str, Any]) -> dict[str, Any]:
    """Merge sets and prefer CNA values, then NVD, independently per score version."""
    nvd = sources.get("nvd", {}).get("cve", sources.get("nvd", {}))
    mitre = sources.get("mitre", {})
    cna = mitre.get("containers", {}).get("cna", {})
    containers = [cna, *mitre.get("containers", {}).get("adp", [])]
    description = _english(cna.get("descriptions", [])) or _english(nvd.get("descriptions", []))
    description_source = "mitre" if _english(cna.get("descriptions", [])) else "nvd"
    metrics: dict[str, dict[str, Any]] = {}
    for version in CVSS_VERSIONS:
        mitre_key = "cvssV" + version.replace(".", "_")
        for container in containers:
            for metric in container.get("metrics", []):
                selected = _score(metric.get(mitre_key, {}), "mitre")
                if selected is not None:
                    metrics[version] = selected
                    break
            if version in metrics:
                break
        if version in metrics:
            continue
        nvd_key = "cvssMetricV" + ("2" if version == "2.0" else version.replace(".", ""))
        # Prefer NVD's primary assessment over a secondary assessment of the same version.
        entries = sorted(
            nvd.get("metrics", {}).get(nvd_key, []), key=lambda item: item.get("type") != "Primary"
        )
        for metric in entries:
            selected = _score(metric.get("cvssData", {}), "nvd")
            if selected is not None:
                metrics[version] = selected
                break

    references: set[str] = set()
    weaknesses: set[str] = set()
    for item in nvd.get("references", []):
        if isinstance(item.get("url"), str):
            references.add(item["url"])
    for weakness in nvd.get("weaknesses", []):
        weaknesses.update(_cwes(weakness.get("description", [])))
    cpes: set[str] = set()
    affected: list[dict[str, Any]] = []
    products: set[tuple[str, str]] = set()
    for criterion in extract_vulnerable_cpe_matches(sources.get("nvd", {})):
        cpes.add(criterion["criteria"])
        affected.append(
            {
                key: value
                for key, value in criterion.items()
                if key
                in {
                    "criteria",
                    "versionStartIncluding",
                    "versionStartExcluding",
                    "versionEndIncluding",
                    "versionEndExcluding",
                }
            }
        )
    for container in containers:
        for reference in container.get("references", []):
            if isinstance(reference.get("url"), str):
                references.add(reference["url"])
        for problem in container.get("problemTypes", []):
            weaknesses.update(_cwes(problem.get("descriptions", [])))
        for item in container.get("affected", []):
            cpes.update(cpe for cpe in item.get("cpes", []) if isinstance(cpe, str))
            vendor, product = item.get("vendor"), item.get("product")
            if vendor and product and vendor.lower() not in {"n/a", "unknown"}:
                products.add((vendor, product))
            affected.append(
                {
                    key: item[key]
                    for key in (
                        "vendor",
                        "product",
                        "defaultStatus",
                        "versions",
                        "platforms",
                        "modules",
                    )
                    if key in item
                }
            )
    for value in cpes:
        try:
            cpe = Cpe23.parse(value)
            if cpe.vendor not in {"*", "-"} and cpe.product not in {"*", "-"}:
                products.add((cpe.vendor, cpe.product))
        except InvalidCpe:
            continue
    selected_score = next(
        (metrics[version]["score"] for version in CVSS_VERSIONS if version in metrics), None
    )
    return {
        "title": cna.get("title"),
        "description": description,
        "description_source": description_source if description else None,
        "state": mitre.get("cveMetadata", {}).get("state") or nvd.get("vulnStatus"),
        "cvss": metrics,
        "cvss_score": selected_score,
        "references": sorted(references),
        "weaknesses": sorted(weaknesses),
        "cpes": sorted(cpes),
        "affected": _canonical_items(affected),
        "products": [
            {"vendor": vendor, "product": product} for vendor, product in sorted(products)
        ],
    }


def meaningful_changes(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Metadata timestamps, ordering, and provenance-only updates do not reopen alerts."""
    ignored = {"description_source"}

    def comparable(field: str, value: Any) -> Any:
        if field == "cvss" and isinstance(value, dict):
            return {
                version: {key: item for key, item in metric.items() if key != "source"}
                for version, metric in value.items()
            }
        return value

    return {
        field: {"old": previous.get(field), "new": current.get(field)}
        for field in sorted(set(previous) | set(current))
        if field not in ignored
        and comparable(field, previous.get(field)) != comparable(field, current.get(field))
    }


def _english(items: list[dict[str, Any]]) -> str | None:
    return next(
        (
            item["value"].strip()
            for item in items
            if item.get("lang", "").startswith("en") and item.get("value")
        ),
        None,
    )


def _score(data: dict[str, Any], source: str) -> dict[str, Any] | None:
    value = data.get("baseScore")
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value <= 10:
        return None
    return {"score": float(value), "vector": data.get("vectorString"), "source": source}


def _cwes(items: list[dict[str, Any]]) -> set[str]:
    values: set[str] = set()
    for item in items:
        for text in (item.get("cweId", ""), item.get("value", ""), item.get("description", "")):
            values.update(re.findall(r"CWE-\d+", text, re.IGNORECASE))
    return {value.upper() for value in values}


def _canonical_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Recursively sort arrays so feed ordering changes do not produce history noise.
    def canonical(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: canonical(item) for key, item in sorted(value.items())}
        if isinstance(value, list):
            return sorted(
                (canonical(item) for item in value),
                key=lambda item: json.dumps(item, sort_keys=True),
            )
        return value

    by_key = {
        json.dumps(canonical(item), sort_keys=True): canonical(item) for item in items if item
    }
    return [by_key[key] for key in sorted(by_key)]
