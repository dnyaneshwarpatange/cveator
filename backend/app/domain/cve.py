from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

SourceName = Literal["nvd", "mitre", "cisa_kev", "epss"]


@dataclass(frozen=True, slots=True)
class NormalizedCve:
    """A source record normalized only as far as the core needs to query it."""

    cve_id: str
    source: SourceName
    raw: dict[str, Any]
    cvss_score: float | None = None
    epss_score: float | None = None
    is_kev: bool | None = None
    published_at: datetime | None = None
    last_modified_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class FetchResult:
    records: list[NormalizedCve]
    # A source-owned high-water mark that is safe to persist only after every record succeeds.
    next_cursor: datetime


@dataclass(frozen=True, slots=True)
class ProductCandidate:
    id: int
    cpe_string: str
