from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx

from app.core.time import parse_upstream_datetime, utc_now
from app.domain.cve import FetchResult, NormalizedCve


class MitreCveListFeed:
    """Reads the official CVE List V5 rolling delta log and its source-record URLs."""

    source_name = "mitre"

    def __init__(
        self,
        *,
        delta_log_url: str,
        client: httpx.Client | None = None,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        self._delta_log_url = delta_log_url
        self._client = client or httpx.Client(timeout=60.0)
        self._owns_client = client is None
        self._now = now

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def fetch_since(self, since: datetime) -> FetchResult:
        if since.tzinfo is None:
            raise ValueError("MITRE cursor must be timezone-aware")
        response = self._client.get(self._delta_log_url)
        response.raise_for_status()
        changes = response.json()
        changed_records = _changed_records_since(changes, since.astimezone(UTC))
        records = [self._fetch_record(change) for change in changed_records.values()]
        return FetchResult(records=records, next_cursor=self._latest_fetch_time(changes))

    def _fetch_record(self, change: dict[str, Any]) -> NormalizedCve:
        response = self._client.get(change["githubLink"])
        response.raise_for_status()
        return normalize_mitre_record(response.json())

    def _latest_fetch_time(self, changes: list[dict[str, Any]]) -> datetime:
        timestamps = [parse_upstream_datetime(entry.get("fetchTime")) for entry in changes]
        valid_timestamps = [timestamp for timestamp in timestamps if timestamp is not None]
        return max(valid_timestamps, default=self._now().astimezone(UTC))


def _changed_records_since(
    changes: list[dict[str, Any]], since: datetime
) -> dict[str, dict[str, Any]]:
    """Return one current source URL per CVE across overlapping log entries."""
    changed: dict[str, dict[str, Any]] = {}
    for entry in changes:
        fetch_time = parse_upstream_datetime(entry.get("fetchTime"))
        if fetch_time is None or fetch_time < since:
            continue
        for change in [*entry.get("new", []), *entry.get("updated", [])]:
            changed[change["cveId"]] = change
    return changed


def normalize_mitre_record(payload: dict[str, Any]) -> NormalizedCve:
    metadata = payload["cveMetadata"]
    return NormalizedCve(
        cve_id=metadata["cveId"],
        source="mitre",
        raw=payload,
        cvss_score=_extract_mitre_cvss_score(payload.get("containers", {})),
        published_at=parse_upstream_datetime(metadata.get("datePublished")),
        last_modified_at=parse_upstream_datetime(metadata.get("dateUpdated")),
    )


def _extract_mitre_cvss_score(containers: dict[str, Any]) -> float | None:
    container_values = [containers.get("cna", {}), *containers.get("adp", [])]
    for container in container_values:
        for metric in container.get("metrics", []):
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                score = metric.get(key, {}).get("baseScore")
                if score is not None:
                    return float(score)
    return None
