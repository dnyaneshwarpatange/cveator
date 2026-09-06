from unittest.mock import Mock

from sqlalchemy.dialects import postgresql

from app.repositories.sqlalchemy_cve_repository import SqlAlchemyCveRepository


def test_match_insert_flushes_a_new_cve_before_resolving_its_foreign_key() -> None:
    session = Mock()
    session.scalar.return_value = 42
    session.execute.return_value.rowcount = 1
    repository = SqlAlchemyCveRepository(session)

    created = repository.create_cve_product_matches("CVE-2026-0001", {7})

    assert created == 1
    session.flush.assert_called_once_with()
    session.scalar.assert_called_once()
    session.execute.assert_called_once()


def test_reconciliation_removes_stale_matches_even_when_nothing_matches() -> None:
    session = Mock()
    session.scalar.return_value = 42
    SqlAlchemyCveRepository(session).reconcile_cve_product_matches("CVE-2026-0001", set())
    statement = session.execute.call_args.args[0]
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "DELETE FROM cve_product_matches" in sql
    assert "cve_product_matches.cve_id" in sql


def test_candidates_include_whole_vendor_subscription() -> None:
    session = Mock()
    session.execute.return_value = []
    SqlAlchemyCveRepository(session).find_product_candidates(
        part="a", vendor="acme", product="widget"
    )
    statement = session.execute.call_args.args[0]
    params = statement.compile(dialect=postgresql.dialect()).params
    assert "widget" in params.values()
    assert "*" in params.values()


def test_candidate_search_uses_only_subscribed_products() -> None:
    session = Mock()
    session.execute.return_value = []
    SqlAlchemyCveRepository(session).find_product_candidates(
        part="a", vendor="acme", product="widget"
    )
    sql = str(session.execute.call_args.args[0].compile(dialect=postgresql.dialect()))
    assert "EXISTS (SELECT watchlist_items.id" in sql
    assert "watchlist_items.product_id = products.id" in sql


def test_name_only_candidates_require_all_versions_and_subscription() -> None:
    session = Mock()
    session.execute.return_value = []
    SqlAlchemyCveRepository(session).find_family_candidates(vendor="acme", product="my_tool")
    statement = session.execute.call_args.args[0].compile(dialect=postgresql.dialect())
    assert "products.cpe_version =" in str(statement)
    assert "EXISTS (SELECT watchlist_items.id" in str(statement)
    assert "my_tool" in statement.params.values()
