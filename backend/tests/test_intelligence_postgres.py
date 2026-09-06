"""Opt-in real PostgreSQL regressions; every test rolls its writes back."""

import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.api.intelligence import browse_cves
from app.api.watchlist import AddWatchlistItemRequest, add_watchlist_item
from app.domain.auth import OrganizationRole, Principal
from app.models.catalog import Organization, Product
from app.models.cve import Cve
from app.models.product_sync import ProductSync


@pytest.fixture
def postgres_session():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL is required for PostgreSQL integration tests")
    engine = create_engine(url)
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection) as session:
            yield session
        transaction.rollback()
    engine.dispose()


def test_vendor_and_product_must_belong_to_same_identity(postgres_session):
    marker = str(uuid4())
    postgres_session.add_all([
        Cve(cve_id="CVE-2099-9876541", normalized_json={
            "description": marker,
            "products": [{"vendor": "atlassian", "product": "jira"}],
        }),
        Cve(cve_id="CVE-2099-9876542", normalized_json={
            "description": marker,
            "products": [{"vendor": "atlassian", "product": "confluence"},
                         {"vendor": "jenkins", "product": "jira"}],
        }),
        Cve(cve_id="CVE-2099-9876543", normalized_json={"description": marker}),
    ])
    postgres_session.flush()
    result = browse_cves(None, postgres_session, q=marker, vendor="atlassian", product="jira")
    assert result["total"] == 1
    assert result["items"][0]["cve_id"] == "CVE-2099-9876541"


def test_filter_treats_sql_wildcards_as_literal_text(postgres_session):
    marker = str(uuid4())
    postgres_session.add(Cve(cve_id="CVE-2099-9876544", normalized_json={
        "description": marker, "products": [{"vendor": "test_vendor", "product": "100%"}],
    }))
    postgres_session.flush()
    assert browse_cves(None, postgres_session, q=marker, vendor="test_vendor",
                       product="100%") ["total"] == 1
    assert browse_cves(None, postgres_session, q=marker, vendor="test%") ["total"] == 0


@pytest.mark.parametrize("previous,expected", [
    ("cancelled", "pending"), ("failed", "pending"),
    ("running", "running"), ("complete", "complete"),
])
def test_resubscribing_recovers_cancelled_work_without_resetting_active_work(
    postgres_session, previous, expected,
):
    org = Organization(name="Rollback-only integration test")
    identity = uuid4().hex
    product = Product(part="a", vendor="integration_test", product_name=identity,
                      cpe_product=identity, cpe_version="*", is_family=True,
                      cpe_string=f"cpe:2.3:a:integration_test:{identity}:*:*:*:*:*:*:*:*")
    postgres_session.add_all([org, product])
    postgres_session.flush()
    state = ProductSync(product_id=product.id, status=previous)
    postgres_session.add(state)
    postgres_session.flush()
    principal = Principal(user_id=uuid4(), org_id=org.id, email="test@example.invalid",
                          role=OrganizationRole.OWNER, token_version=0)
    add_watchlist_item(AddWatchlistItemRequest(product_id=product.id), principal, postgres_session)
    postgres_session.refresh(state)
    assert state.status == expected
