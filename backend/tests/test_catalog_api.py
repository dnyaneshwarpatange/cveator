import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

import httpx

from app.db.session import get_session
from app.main import app


def test_product_search_returns_human_facing_catalog_fields() -> None:
    session = Mock()
    session.scalars.return_value = [
        SimpleNamespace(
            id=7,
            vendor="intuit",
            product_name="Intuit QuickBooks Desktop 2024",
            cpe_version="2024",
        )
    ]

    def override_session() -> object:
        yield session

    app.dependency_overrides[get_session] = override_session
    try:
        response = _request("/catalog/products", params={"q": "quickbooks"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == [
        {
            "id": 7,
            "vendor": "intuit",
            "product_name": "Intuit QuickBooks Desktop 2024",
            "version": "2024",
        }
    ]
    session.scalars.assert_called_once()


def test_product_search_rejects_too_short_queries() -> None:
    response = _request("/catalog/products", params={"q": "q"})

    assert response.status_code == 422


def _request(path: str, *, params: dict[str, str]) -> httpx.Response:
    async def request() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.get(path, params=params)

    return asyncio.run(request())
