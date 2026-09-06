import re
from dataclasses import dataclass
from typing import Any


class InvalidCpe(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Cpe23:
    part: str
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str

    @classmethod
    def parse(cls, value: str) -> "Cpe23":
        fields = _split_cpe_23(value)
        if len(fields) != 13 or fields[:2] != ["cpe", "2.3"]:
            raise InvalidCpe(f"Expected a CPE 2.3 formatted string: {value}")
        return cls(*fields[2:])


def extract_vulnerable_cpe_matches(nvd_payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten NVD's nested configuration tree without imposing its operator semantics twice."""
    cve = nvd_payload.get("cve", nvd_payload)
    matches: list[dict[str, Any]] = []

    def walk(node: dict[str, Any]) -> None:
        for match in node.get("cpeMatch", []):
            if match.get("vulnerable", False) and match.get("criteria"):
                matches.append(match)
        for child in node.get("nodes", []):
            walk(child)

    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            walk(node)
    return matches


def product_matches_cpe_criterion(product: Cpe23, criterion: dict[str, Any]) -> bool:
    """Evaluate one NVD CPE match expression against a catalog product CPE."""
    criteria = Cpe23.parse(criterion["criteria"])
    if not all(
        _components_compatible(candidate, expected)
        for candidate, expected in (
            (product.part, criteria.part),
            (product.vendor, criteria.vendor),
            (product.product, criteria.product),
            (product.update, criteria.update),
            (product.edition, criteria.edition),
            (product.language, criteria.language),
            (product.sw_edition, criteria.sw_edition),
            (product.target_sw, criteria.target_sw),
            (product.target_hw, criteria.target_hw),
            (product.other, criteria.other),
        )
    ):
        return False
    return _version_matches(product.version, criteria.version, criterion)


def _split_cpe_23(value: str) -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current).lower())
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    fields.append("".join(current).lower())
    return fields


def _components_compatible(candidate: str, expected: str) -> bool:
    return candidate == "*" or expected == "*" or candidate == expected


def _version_matches(
    product_version: str, criteria_version: str, criterion: dict[str, Any]
) -> bool:
    if not _components_compatible(product_version, criteria_version):
        return False
    # A generic dictionary CPE (version *) intentionally represents every version.
    if product_version == "*":
        return True

    start_including = criterion.get("versionStartIncluding")
    start_excluding = criterion.get("versionStartExcluding")
    end_including = criterion.get("versionEndIncluding")
    end_excluding = criterion.get("versionEndExcluding")
    if start_including is not None and _compare_versions(product_version, start_including) < 0:
        return False
    if start_excluding is not None and _compare_versions(product_version, start_excluding) <= 0:
        return False
    if end_including is not None and _compare_versions(product_version, end_including) > 0:
        return False
    return end_excluding is None or _compare_versions(product_version, end_excluding) < 0


def _compare_versions(left: str, right: str) -> int:
    """Stable comparison for CPE's heterogeneous version labels.

    It preserves natural numeric ordering (1.10 > 1.2) and gracefully handles labels
    such as `2024r1` without treating them as invalid Python package versions.
    """
    left_tokens = _version_tokens(left)
    right_tokens = _version_tokens(right)
    for left_token, right_token in zip(left_tokens, right_tokens, strict=False):
        if left_token == right_token:
            continue
        if isinstance(left_token, int) and isinstance(right_token, int):
            return -1 if left_token < right_token else 1
        return -1 if str(left_token) < str(right_token) else 1
    if len(left_tokens) == len(right_tokens):
        return 0
    longer = left_tokens if len(left_tokens) > len(right_tokens) else right_tokens
    remainder = longer[min(len(left_tokens), len(right_tokens)) :]
    if all(token == 0 for token in remainder):
        return 0
    return 1 if len(left_tokens) > len(right_tokens) else -1


def _version_tokens(value: str) -> list[int | str]:
    return [
        int(token) if token.isdigit() else token.lower()
        for token in re.findall(r"\d+|[A-Za-z]+", value)
    ]
