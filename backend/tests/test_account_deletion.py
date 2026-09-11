from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.services.account_deletion import AccountDeletion


def setup_service(monkeypatch, role="member", admin=False, other_owner=True):
    user = SimpleNamespace(id=uuid4(), org_id=uuid4(), email="delete@example.com", token_version=0, role=role)
    session, redis, sender = Mock(), Mock(), Mock()
    session.scalar.side_effect = [Mock(), user, uuid4() if other_owner else None]
    redis.eval.return_value = 1
    monkeypatch.setattr("app.services.account_deletion.is_application_admin", lambda _: admin)
    return AccountDeletion(session, redis, sender, "test-secret"), user


def test_start_emails_only_registered_address_and_does_not_delete(monkeypatch):
    service, user = setup_service(monkeypatch)
    result = service.start(SimpleNamespace(user_id=user.id, org_id=user.org_id, token_version=0))
    assert result["expires_in_seconds"] == 600
    assert service.sender.send.call_args.args[0].recipient == user.email
    assert service.redis.set.call_args.kwargs["ex"] == 600
    service.session.delete.assert_not_called()


@pytest.mark.parametrize("admin,role,other", [(True, "member", True), (False, "owner", False)])
def test_protected_accounts_cannot_request_deletion(monkeypatch, admin, role, other):
    service, user = setup_service(monkeypatch, role, admin, other)
    with pytest.raises(HTTPException) as exc:
        service.start(SimpleNamespace(user_id=user.id, org_id=user.org_id, token_version=0))
    assert exc.value.status_code == 409
    service.sender.send.assert_not_called()
    service.session.delete.assert_not_called()


@pytest.mark.parametrize("valid", [0, 1])
def test_delete_requires_successful_atomic_verification(monkeypatch, valid):
    service, user = setup_service(monkeypatch)
    service.redis.eval.return_value = valid
    principal = SimpleNamespace(user_id=user.id, org_id=user.org_id, token_version=0)
    if valid:
        service.confirm(principal, uuid4(), "123456")
        service.session.delete.assert_called_once_with(user)
    else:
        with pytest.raises(HTTPException):
            service.confirm(principal, uuid4(), "123456")
        service.session.delete.assert_not_called()


def test_digest_bound_to_user_email_session_and_challenge(monkeypatch):
    service, user = setup_service(monkeypatch)
    challenge = str(uuid4())
    original = service.digest(user, challenge, "123456")
    assert original != service.digest(user, str(uuid4()), "123456")
    user.token_version += 1
    assert original != service.digest(user, challenge, "123456")


def test_smtp_failure_invalidates_challenge(monkeypatch):
    service, user = setup_service(monkeypatch)
    service.sender.send.side_effect = RuntimeError("SMTP unavailable")
    with pytest.raises(RuntimeError):
        service.start(SimpleNamespace(user_id=user.id, org_id=user.org_id, token_version=0))
    service.redis.delete.assert_called_once_with(f"account-delete:{user.id}")
    service.session.delete.assert_not_called()
