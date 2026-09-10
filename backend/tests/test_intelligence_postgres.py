"""Opt-in real PostgreSQL regressions; every test rolls its writes back."""

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.api.intelligence import browse_cves
from app.api.watchlist import AddWatchlistItemRequest, add_watchlist_item
from app.domain.auth import OrganizationRole, Principal
from app.models.billing import Subscription
from app.models.catalog import Organization, Product
from app.models.cve import Cve
from app.models.product_sync import ProductSync
from app.services.access import monitoring_access, monitoring_access_condition


@pytest.fixture
def postgres_session():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL is required for PostgreSQL integration tests")
    engine = create_engine(
        url, connect_args={"connect_timeout": 10, "options": "-c statement_timeout=30000"}
    )
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection) as session:
            yield session
        transaction.rollback()
    engine.dispose()


def test_vendor_and_product_must_belong_to_same_identity(postgres_session):
    marker = str(uuid4())
    postgres_session.add_all(
        [
            Cve(
                cve_id="CVE-2099-9876541",
                normalized_json={
                    "description": marker,
                    "products": [{"vendor": "atlassian", "product": "jira"}],
                },
            ),
            Cve(
                cve_id="CVE-2099-9876542",
                normalized_json={
                    "description": marker,
                    "products": [
                        {"vendor": "atlassian", "product": "confluence"},
                        {"vendor": "jenkins", "product": "jira"},
                    ],
                },
            ),
            Cve(cve_id="CVE-2099-9876543", normalized_json={"description": marker}),
        ]
    )
    postgres_session.flush()
    result = browse_cves(None, postgres_session, q=marker, vendor="atlassian", product="jira")
    assert result["total"] == 1
    assert result["items"][0]["cve_id"] == "CVE-2099-9876541"


def test_filter_treats_sql_wildcards_as_literal_text(postgres_session):
    marker = str(uuid4())
    postgres_session.add(
        Cve(
            cve_id="CVE-2099-9876544",
            normalized_json={
                "description": marker,
                "products": [{"vendor": "test_vendor", "product": "100%"}],
            },
        )
    )
    postgres_session.flush()
    assert (
        browse_cves(None, postgres_session, q=marker, vendor="test_vendor", product="100%")["total"]
        == 1
    )
    assert browse_cves(None, postgres_session, q=marker, vendor="test%")["total"] == 0


@pytest.mark.parametrize(
    "previous,expected",
    [
        ("cancelled", "pending"),
        ("failed", "pending"),
        ("running", "running"),
        ("complete", "complete"),
    ],
)
def test_resubscribing_recovers_cancelled_work_without_resetting_active_work(
    postgres_session,
    previous,
    expected,
):
    org = Organization(name="Rollback-only integration test")
    identity = uuid4().hex
    product = Product(
        part="a",
        vendor="integration_test",
        product_name=identity,
        cpe_product=identity,
        cpe_version="*",
        is_family=True,
        cpe_string=f"cpe:2.3:a:integration_test:{identity}:*:*:*:*:*:*:*:*",
    )
    postgres_session.add_all([org, product])
    postgres_session.flush()
    state = ProductSync(product_id=product.id, status=previous)
    postgres_session.add(state)
    postgres_session.flush()
    principal = Principal(
        user_id=uuid4(),
        org_id=org.id,
        email="test@example.invalid",
        role=OrganizationRole.OWNER,
        token_version=0,
    )
    add_watchlist_item(AddWatchlistItemRequest(product_id=product.id), principal, postgres_session)
    postgres_session.refresh(state)
    assert state.status == expected


def test_trial_and_paid_access_use_real_tenant_scoped_queries(postgres_session):
    now = datetime.now(UTC)
    expired = Organization(name="Expired rollback trial", created_at=now - timedelta(days=4))
    fresh = Organization(name="Fresh rollback trial", created_at=now - timedelta(days=1))
    postgres_session.add_all([expired, fresh])
    postgres_session.flush()
    assert not monitoring_access(postgres_session, expired.id)["has_access"]
    assert monitoring_access(postgres_session, fresh.id)["status"] == "trial"
    subscription = Subscription(
        org_id=expired.id,
        payment_provider="test",
        provider_subscription_id=uuid4().hex,
        plan_id="starter_monthly",
        status="created",
        current_period_end=now + timedelta(days=30),
    )
    postgres_session.add(subscription)
    postgres_session.flush()
    assert not monitoring_access(postgres_session, expired.id)["has_access"]
    subscription.status = "active"
    postgres_session.flush()
    assert not monitoring_access(postgres_session, expired.id)["has_access"]
    subscription.last_provider_event_at = now
    postgres_session.flush()
    assert monitoring_access(postgres_session, expired.id)["status"] == "active"
    assert monitoring_access(postgres_session, fresh.id)["status"] == "trial"
    assert postgres_session.scalar(select(monitoring_access_condition(expired.id)))
    subscription.current_period_end = now - timedelta(seconds=1)
    postgres_session.flush()
    assert not postgres_session.scalar(select(monitoring_access_condition(expired.id)))


def test_signup_verification_is_atomic_and_cannot_be_replayed(postgres_session, monkeypatch):
    import re
    from unittest.mock import Mock

    from fastapi import HTTPException

    from app.api import auth
    from app.models.catalog import User
    from app.models.signup import PendingSignup
    from app.repositories.sqlalchemy_auth_repository import SqlAlchemyAuthRepository
    from app.services.auth import AuthService
    from app.services.signup import SignupService

    sender = Mock()
    service = SignupService(postgres_session, sender, "test-only-key")
    monkeypatch.setattr(auth, "_signup_service", lambda _: service)
    monkeypatch.setattr(auth, "_enforce_signup_ip_limit", lambda *_, **__: None)
    email = f"otp-{uuid4().hex}@example.com"
    challenge = auth.register_owner(
        auth.RegisterRequest(
            organization_name="Rollback OTP test", email=email, password="Strong-test-password!"
        ),
        Mock(),
        postgres_session,
    )
    assert not hasattr(challenge, "access_token")
    assert postgres_session.scalar(select(User).where(User.email == email)) is None
    code = re.search(r"\b[0-9]{6}\b", sender.send.call_args.args[0].text_body).group()
    wrong = "000000" if code != "000000" else "111111"
    with pytest.raises(HTTPException):
        auth.verify_signup(
            auth.VerifySignupRequest(challenge_id=challenge.challenge_id, code=wrong),
            Mock(),
            postgres_session,
        )
    assert postgres_session.get(PendingSignup, challenge.challenge_id).attempts == 1
    verified = auth.verify_signup(
        auth.VerifySignupRequest(challenge_id=challenge.challenge_id, code=code),
        Mock(),
        postgres_session,
    )
    assert verified.access_token
    assert postgres_session.get(PendingSignup, challenge.challenge_id) is None
    user = AuthService(SqlAlchemyAuthRepository(postgres_session)).authenticate(
        email=email, password="Strong-test-password!"
    )
    assert monitoring_access(postgres_session, user.org_id)["status"] == "trial"
    with pytest.raises(HTTPException):
        auth.verify_signup(
            auth.VerifySignupRequest(challenge_id=challenge.challenge_id, code=code),
            Mock(),
            postgres_session,
        )
