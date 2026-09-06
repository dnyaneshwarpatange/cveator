import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from fastapi import HTTPException

import app.api.auth as auth_api
import app.core.readiness as readiness_module
from app.core.config import Settings
from app.core.readiness import check_readiness
from app.main import app


def test_readiness_checks_database_and_redis(monkeypatch) -> None:
    session = Mock()
    redis = Mock()
    redis.ping.return_value = True
    monkeypatch.setattr(readiness_module.Redis, "from_url", Mock(return_value=redis))
    result = check_readiness(session, Settings(redis_url="redis://example.test/0"))

    assert result.ready
    session.execute.assert_called_once()
    redis.ping.assert_called_once()
    redis.close.assert_called_once()


def test_api_emits_request_ids_security_headers_and_metrics() -> None:
    response = _request("GET", "/healthz", headers={"x-request-id": "request_12345678"})

    assert response.status_code == 200
    assert response.headers["x-request-id"] == "request_12345678"
    assert response.headers["x-content-type-options"] == "nosniff"

    metrics = _request("GET", "/metrics")
    assert metrics.status_code == 200
    assert "cve_monitor_http_requests_total" in metrics.text


def test_authentication_rate_limit_returns_retry_after(monkeypatch) -> None:
    limiter = Mock()
    limiter.allow.return_value = False
    monkeypatch.setattr(auth_api, "_rate_limiter", lambda *_: limiter)
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"))

    with pytest.raises(HTTPException) as error:
        auth_api._enforce_auth_rate_limit(
            request=request,
            email="owner@example.com",
            action="login",
        )

    assert error.value.status_code == 429
    assert "Retry-After" in error.value.headers


def test_webhook_rejects_oversized_body_before_provider_processing() -> None:
    response = _request(
        "POST",
        "/billing/webhooks/configured-provider",
        content=b"{}",
        headers={"content-length": "1048577"},
    )

    assert response.status_code == 413


def _request(
    method: str,
    path: str,
    *,
    content: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    async def request() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, path, content=content, headers=headers)

    return asyncio.run(request())
