from io import BytesIO
from unittest.mock import Mock

from botocore.exceptions import ClientError

from app.adapters.s3_storage import S3StorageProvider


def test_s3_protocol_adapter_keeps_bucket_and_provider_details_out_of_core() -> None:
    client = Mock()
    client.put_object.return_value = {"ETag": '"abc123"'}
    client.get_object.return_value = {"Body": BytesIO(b"stored payload")}
    provider = S3StorageProvider(bucket="private-bucket", client=client)

    stored = provider.put(
        key="reports/acme.json",
        content=b"stored payload",
        content_type="application/json",
    )

    assert stored.key == "reports/acme.json"
    assert stored.size == 14
    assert stored.etag == "abc123"
    assert provider.get(key=stored.key) == b"stored payload"
    assert provider.exists(key=stored.key)
    provider.delete(key=stored.key)
    client.put_object.assert_called_once_with(
        Bucket="private-bucket",
        Key="reports/acme.json",
        Body=b"stored payload",
        ContentType="application/json",
    )


def test_s3_protocol_adapter_returns_false_only_for_not_found() -> None:
    client = Mock()
    client.head_object.side_effect = ClientError(
        {"Error": {"Code": "NoSuchKey"}, "ResponseMetadata": {"HTTPStatusCode": 404}},
        "HeadObject",
    )
    provider = S3StorageProvider(bucket="private-bucket", client=client)

    assert not provider.exists(key="missing")
