from typing import BinaryIO, Protocol

from app.domain.storage import StoredObject


class StorageProvider(Protocol):
    """Boundary for S3-compatible, self-hosted object storage."""

    def put(
        self, *, key: str, content: bytes | BinaryIO, content_type: str
    ) -> StoredObject: ...

    def get(self, *, key: str) -> bytes: ...

    def delete(self, *, key: str) -> None: ...

    def exists(self, *, key: str) -> bool: ...
