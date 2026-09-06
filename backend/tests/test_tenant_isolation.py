from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

from sqlalchemy.dialects import postgresql

from app.repositories.sqlalchemy_auth_repository import SqlAlchemyAuthRepository
from app.repositories.sqlalchemy_watchlist_repository import SqlAlchemyWatchlistRepository


def test_watchlist_reads_and_deletes_are_scoped_to_the_repository_organization() -> None:
    organization_id = uuid4()
    session = Mock()
    session.scalars.return_value = []
    session.execute.return_value.rowcount = 1
    repository = SqlAlchemyWatchlistRepository(session, org_id=organization_id)

    repository.list_products()
    select_statement = session.scalars.call_args.args[0]
    compiled_select = select_statement.compile(dialect=postgresql.dialect())
    assert "watchlist_items.org_id" in str(compiled_select)
    assert organization_id in compiled_select.params.values()

    repository.remove_product(99)
    delete_statement = session.execute.call_args.args[0]
    compiled_delete = delete_statement.compile(dialect=postgresql.dialect())
    assert "watchlist_items.org_id" in str(compiled_delete)
    assert organization_id in compiled_delete.params.values()


def test_watchlist_add_binds_the_repository_organization_not_client_input() -> None:
    organization_id = uuid4()
    session = Mock()
    session.scalar.return_value = SimpleNamespace(
        id=17,
        vendor="intuit",
        product_name="QuickBooks Desktop",
        cpe_version="2024",
    )
    repository = SqlAlchemyWatchlistRepository(session, org_id=organization_id)

    added = repository.add_product(17)

    assert added is not None
    statement = session.execute.call_args.args[0]
    compiled = statement.compile(dialect=postgresql.dialect())
    assert organization_id in compiled.params.values()


def test_organization_member_listing_cannot_escape_its_tenant_filter() -> None:
    organization_id = uuid4()
    session = Mock()
    session.scalars.return_value = []

    SqlAlchemyAuthRepository(session).list_by_org(organization_id)

    statement = session.scalars.call_args.args[0]
    compiled = statement.compile(dialect=postgresql.dialect())
    assert "users.org_id" in str(compiled)
    assert organization_id in compiled.params.values()
