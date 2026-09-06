from typing import BinaryIO

import boto3
from botocore.client import BaseClient
from botocore.config import Config
from botocore.exceptions import ClientError

from app.core.config import Settings
from app.domain.storage import StoredObject


class S3StorageProvider:
    """S3-protocol adapter; endpoint configuration determines the self-hosted server."""

    def __init__(self, *, bucket: str, client: BaseClient) -> None:
        self._bucket = bucket
        self._client = client

    @classmethod
    def from_settings(cls, settings: Settings) -> "S3StorageProvider":
        settings.validate_storage_configuration()
        access_key = (
            settings.storage_access_key.get_secret_value()
            if settings.storage_access_key
            else ""
        )
        secret_key = (
            settings.storage_secret_key.get_secret_value()
            if settings.storage_secret_key
            else ""
        )
        client = boto3.client(
            "s3",
            endpoint_url=settings.storage_endpoint_url,
            region_name=settings.storage_region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        )
        return cls(bucket=settings.storage_bucket, client=client)

    def put(
        self, *, key: str, content: bytes | BinaryIO, content_type: str
    ) -> StoredObject:
        response = self._client.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=content,
            ContentType=content_type,
        )
        size = len(content) if isinstance(content, bytes) else 0
        return StoredObject(
            key=key,
            size=size,
            etag=_clean_etag(response.get("ETag")),
        )

    def get(self, *, key: str) -> bytes:
        response = self._client.get_object(Bucket=self._bucket, Key=key)
        return response["Body"].read()

    def delete(self, *, key: str) -> None:
        self._client.delete_object(Bucket=self._bucket, Key=key)

    def exists(self, *, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
        except ClientError as error:
            status_code = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status_code == 404:
                return False
            raise
        return True


def _clean_etag(value: object) -> str | None:
    return str(value).strip('"') if value else None
