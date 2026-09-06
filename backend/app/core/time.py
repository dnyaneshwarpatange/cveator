from datetime import UTC, datetime


def parse_upstream_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        # NVD's live API currently emits ISO 8601 timestamps without a suffix.
        # Its API dates are UTC, while CVE List V5 sends an explicit Z suffix.
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def utc_now() -> datetime:
    return datetime.now(UTC)
