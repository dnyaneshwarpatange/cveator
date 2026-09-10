from datetime import timedelta
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api import auth
from app.core.time import utc_now
from app.models.catalog import Organization, User
from app.models.signup import PendingSignup
from app.services.signup import SignupMailUnavailable, SignupService, SignupThrottled


def pending(service, *, code="123456"):
    now = utc_now()
    item = PendingSignup(
        id=uuid4(),
        email="signup@example.com",
        organization_name="Test",
        password_hash="already-hashed",
        expires_at=now + timedelta(minutes=10),
        window_started_at=now,
        sent_at=now - timedelta(minutes=2),
        sends=1,
        attempts=0,
    )
    item.code_hash = service._digest(item.id, code)
    return item


def test_start_sends_smtp_port_message_but_creates_no_account(monkeypatch):
    session, sender = Mock(), Mock()
    session.scalar.side_effect = [None, None]
    monkeypatch.setattr("app.services.signup.secrets.randbelow", lambda _: 123456)
    service = SignupService(session, sender, "secret")
    item = service.start(
        organization_name="Team", email="Signup@Example.com", password="a-strong-test-password"
    )
    message = sender.send.call_args.args[0]
    assert message.recipient == "signup@example.com"
    assert "123456" in message.text_body
    assert item.code_hash != "123456"
    assert item.password_hash != "a-strong-test-password"
    assert session.add.call_count == 1
    assert isinstance(session.add.call_args.args[0], PendingSignup)


def test_correct_code_creates_account_and_consumes_challenge():
    session = Mock()
    service = SignupService(session, Mock(), "secret")
    item = pending(service)
    session.scalar.side_effect = [item, None]
    user = service.verify(item.id, "123456")
    assert user.email == item.email
    assert {type(call.args[0]) for call in session.add.call_args_list} == {Organization, User}
    session.delete.assert_called_once_with(item)


def test_wrong_codes_consume_budget_and_correct_code_cannot_bypass_lockout():
    session = Mock()
    service = SignupService(session, Mock(), "secret")
    item = pending(service)
    session.scalar.return_value = item
    for _ in range(5):
        assert service.verify(item.id, "000000") is None
    assert item.attempts == 5
    assert service.verify(item.id, "123456") is None
    session.add.assert_not_called()


def test_expired_or_consumed_code_cannot_create_account():
    session = Mock()
    service = SignupService(session, Mock(), "secret")
    item = pending(service)
    item.expires_at = utc_now() - timedelta(seconds=1)
    session.scalar.side_effect = [item, None]
    assert service.verify(item.id, "123456") is None
    assert service.verify(item.id, "123456") is None
    session.add.assert_not_called()


@pytest.mark.parametrize("field,value", [("sends", 5), ("attempts", 5), ("sent_at", None)])
def test_resend_limits_are_database_backed(field, value):
    session, sender = Mock(), Mock()
    service = SignupService(session, sender, "secret")
    item = pending(service)
    setattr(item, field, utc_now() if value is None else value)
    session.scalar.side_effect = [None, item]
    with pytest.raises(SignupThrottled):
        service.start(organization_name="Team", email=item.email, password="password-for-test")
    sender.send.assert_not_called()


def test_resend_invalidates_old_challenge_without_resetting_guess_budget():
    session = Mock()
    service = SignupService(session, Mock(), "secret")
    item = pending(service)
    previous_id, previous_hash = item.id, item.code_hash
    item.attempts = 3
    session.scalar.side_effect = [None, item]
    result = service.start(organization_name="Team", email=item.email, password="password-for-test")
    assert result.id != previous_id
    assert result.code_hash != previous_hash
    assert result.attempts == 3


def test_smtp_failure_never_returns_a_successful_challenge():
    session, sender = Mock(), Mock()
    session.scalar.side_effect = [None, None]
    sender.send.side_effect = OSError("SMTP unavailable")
    with pytest.raises(SignupMailUnavailable):
        SignupService(session, sender, "secret").start(
            organization_name="Team", email="signup@example.com", password="password-for-test"
        )


def test_verify_route_commits_failed_attempt_and_issues_no_token(monkeypatch):
    session = Mock()
    service = Mock()
    service.verify.return_value = None
    monkeypatch.setattr(auth, "_signup_service", lambda _: service)
    monkeypatch.setattr(auth, "_enforce_signup_ip_limit", lambda *_, **__: None)
    with pytest.raises(HTTPException) as error:
        auth.verify_signup(
            auth.VerifySignupRequest(challenge_id=uuid4(), code="000000"), Mock(), session
        )
    assert error.value.status_code == 400
    session.commit.assert_called_once()


def test_signup_rate_limit_fails_closed_when_redis_is_down(monkeypatch):
    limiter = Mock()
    limiter.allow.side_effect = OSError("Unavailable")
    monkeypatch.setattr(auth, "_rate_limiter", lambda *_: limiter)
    request = Mock()
    request.client.host = "127.0.0.1"
    with pytest.raises(HTTPException) as error:
        auth._enforce_signup_ip_limit(request)
    assert error.value.status_code == 503
