from datetime import UTC, datetime
from unittest.mock import Mock

import httpx
import pytest
from sqlalchemy.dialects import postgresql

from app.adapters.nvd_cpe import NvdCpeDictionaryFeed
from app.domain.product import CatalogPage, CatalogProduct
from app.repositories.sqlalchemy_catalog_repository import (
    SqlAlchemyCatalogRepository,
    product_family,
)
from app.services.catalog import ProductCatalogSyncService


def raw_product(version: str, *, deprecated: bool = False) -> dict:
    return {"cpe": {
        "cpeName": f"cpe:2.3:a:atlassian:jira:{version}:*:*:*:*:*:*:*",
        "deprecated": deprecated,
        "titles": [{"lang": "en", "title": f"Atlassian Jira {version}"}],
    }}


def test_full_import_resumes_actual_upstream_offset_including_deprecated_entries() -> None:
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert "lastModStartDate" not in request.url.params
        index = int(request.url.params["startIndex"])
        if index == 2:
            return httpx.Response(200, json={"totalResults": 5, "products": [
                raw_product("9.12.0"), raw_product("9.11.0", deprecated=True),
            ]})
        assert index == 4
        return httpx.Response(200, json={"totalResults": 5, "products": [raw_product("9.10.0")]})

    feed = NvdCpeDictionaryFeed(
        api_key=None, results_per_page=2, request_interval_seconds=0,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    iterator = feed.iter_pages(start_index=2)
    first = next(iterator)
    assert len(requests) == 1  # Lazy: next page is not fetched before the consumer commits.
    assert first.next_start_index == 4
    assert len(first.products) == 1
    assert not first.complete
    second = next(iterator)
    assert second.complete and second.next_start_index == 5
    with pytest.raises(StopIteration):
        next(iterator)


def test_catalog_retries_temporary_failure_without_skipping_page() -> None:
    calls = 0
    sleeps = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.url.params["startIndex"] == "0"
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "3"})
        return httpx.Response(200, json={"totalResults": 1, "products": [raw_product("9.12.0")]})

    feed = NvdCpeDictionaryFeed(
        api_key=None, results_per_page=2, request_interval_seconds=0,
        client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=sleeps.append,
    )
    assert len(list(feed.iter_pages())) == 1
    assert calls == 2 and sleeps == [3]


def test_missing_page_is_not_marked_complete() -> None:
    feed = NvdCpeDictionaryFeed(
        api_key=None, results_per_page=2, request_interval_seconds=0,
        client=httpx.Client(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"totalResults": 20, "products": []})
        )),
    )
    with pytest.raises(ValueError, match="empty page"):
        list(feed.iter_pages())


def test_family_is_generic_and_preserves_escaped_identity() -> None:
    product = CatalogProduct(
        part="a", vendor="acme", product_name="Acme My:Tool 2.0", cpe_product="my:tool",
        cpe_version="2.0", cpe_string=r"cpe:2.3:a:acme:my\:tool:2.0:*:*:*:*:*:*:*",
    )
    family = product_family(product)
    assert family.cpe_version == "*"
    assert family.cpe_string == r"cpe:2.3:a:acme:my\:tool:*:*:*:*:*:*:*:*"
    assert "2.0" not in family.product_name


def test_bulk_upsert_deduplicates_family_across_versions() -> None:
    session = Mock()
    repository = SqlAlchemyCatalogRepository(session)
    products = [CatalogProduct(
        part="a", vendor="atlassian", product_name=f"Atlassian Jira {version}",
        cpe_product="jira", cpe_version=version,
        cpe_string=f"cpe:2.3:a:atlassian:jira:{version}:*:*:*:*:*:*:*",
    ) for version in ["9.12.0", "9.11.0", "*"]]
    assert repository.upsert_products(products) == 3
    statement = session.execute.call_args.args[0]
    params = statement.compile(dialect=postgresql.dialect()).params
    families = [value for key, value in params.items() if key.startswith("is_family_")]
    assert families.count(True) == 1
    assert len(families) == 3


def test_search_only_returns_families_and_never_ranks_a_different_patch() -> None:
    session = Mock()
    session.scalars.return_value = []
    SqlAlchemyCatalogRepository(session).search("Jira 9.12.36")
    compiled = session.scalars.call_args.args[0].compile(dialect=postgresql.dialect())
    assert "products.is_family IS true" in str(compiled)
    assert "9.12.36" not in compiled.params.values()
    assert "jira" in compiled.params.values()


def test_partial_incremental_window_commits_records_without_advancing_watermark() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2026, 1, 2, tzinfo=UTC)
    repository = Mock()
    repository.get_cursor.return_value = start
    repository.upsert_products.return_value = 1
    feed = Mock(source_name="nvd_cpe_dictionary")

    def pages(**kwargs):
        yield CatalogPage([], 1, 2, end, False)
        raise httpx.ReadTimeout("interrupted")

    feed.iter_pages.side_effect = pages
    commit = Mock()
    with pytest.raises(httpx.ReadTimeout):
        ProductCatalogSyncService(repository, {}).sync_pages(feed, commit_page=commit)
    commit.assert_called_once()
    repository.save_cursor.assert_not_called()
