from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StoredObject:
    key: str
    size: int
    etag: str | None
