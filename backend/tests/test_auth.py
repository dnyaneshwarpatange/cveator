from uuid import uuid4

import jwt
import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.core.security import create_access_token, decode_access_token, verify_password
from app.domain.auth import (
    AuthenticatedUser,
    AuthenticationFailed,
    EmailAlreadyRegistered,
    OrganizationRole,
)
from app.services.auth import AuthService


class FakeAuthRepository:
    def __init__(self) -> None:
        self.users_by_email: dict[str, AuthenticatedUser] = {}
        self.logged_in_user_ids: list[object] = []

    def get_by_email(self, email: str) -> AuthenticatedUser | None:
        return self.users_by_email.get(email)

    def get_by_id(self, user_id: object) -> AuthenticatedUser | None:
        return next((user for user in self.users_by_email.values() if user.id == user_id), None)

    def create_organization_owner(
        self, *, organization_name: str, email: str, password_hash: str
    ) -> AuthenticatedUser:
        del organization_name
        user = AuthenticatedUser(
            id=uuid4(),
            org_id=uuid4(),
            email=email,
            role=OrganizationRole.OWNER,
            password_hash=password_hash,
            token_version=0,
            is_active=True,
        )
        self.users_by_email[email] = user
        return user

    def create_member(
        self, *, org_id: object, email: str, password_hash: str, role: str
    ) -> AuthenticatedUser:
        user = AuthenticatedUser(
            id=uuid4(),
            org_id=org_id,
            email=email,
            role=OrganizationRole(role),
            password_hash=password_hash,
            token_version=0,
            is_active=True,
        )
        self.users_by_email[email] = user
        return user

    def list_by_org(self, org_id: object) -> list[AuthenticatedUser]:
        return [user for user in self.users_by_email.values() if user.org_id == org_id]

    def record_successful_login(self, user_id: object) -> None:
        self.logged_in_user_ids.append(user_id)


def test_owner_registration_normalizes_email_and_stores_only_an_argon2_hash() -> None:
    repository = FakeAuthRepository()
    service = AuthService(repository)

    user = service.register_owner(
        organization_name="Acme IT",
        email=" Owner@Example.COM ",
        password="correct-horse-battery-staple",
    )

    assert user.email == "owner@example.com"
    assert user.role is OrganizationRole.OWNER
    assert user.password_hash != "correct-horse-battery-staple"
    assert user.password_hash.startswith("$argon2")
    assert verify_password("correct-horse-battery-staple", user.password_hash)

    authenticated = service.authenticate(
        email="OWNER@example.com", password="correct-horse-battery-staple"
    )
    assert authenticated.id == user.id
    assert repository.logged_in_user_ids == [user.id]


def test_authentication_never_accepts_an_unknown_or_duplicate_account() -> None:
    repository = FakeAuthRepository()
    service = AuthService(repository)
    service.register_owner(
        organization_name="Acme IT",
        email="owner@example.com",
        password="correct-horse-battery-staple",
    )

    with pytest.raises(EmailAlreadyRegistered):
        service.register_owner(
            organization_name="Another Acme",
            email="OWNER@example.com",
            password="different-correct-horse-password",
        )
    with pytest.raises(AuthenticationFailed):
        service.authenticate(email="nobody@example.com", password="not-the-password")


def test_jwt_requires_issuer_audience_expiry_and_carries_tenant_identity() -> None:
    settings = Settings(
        app_env="production",
        jwt_secret=SecretStr("a" * 64),
        jwt_issuer="test-issuer",
        jwt_audience="test-audience",
    )
    user = AuthenticatedUser(
        id=uuid4(),
        org_id=uuid4(),
        email="owner@example.com",
        role=OrganizationRole.ADMIN,
        password_hash="unused",
        token_version=3,
        is_active=True,
    )

    token = create_access_token(user, settings)
    principal = decode_access_token(token, settings)

    assert principal.user_id == user.id
    assert principal.org_id == user.org_id
    assert principal.role is OrganizationRole.ADMIN
    assert principal.token_version == 3

    incorrect_audience_token = jwt.encode(
        {
            "sub": str(user.id),
            "org_id": str(user.org_id),
            "email": user.email,
            "role": user.role.value,
            "ver": user.token_version,
            "iss": settings.jwt_issuer,
            "aud": "wrong-audience",
            "iat": 0,
            "nbf": 0,
            "exp": 4_102_444_800,
        },
        settings.jwt_secret.get_secret_value(),
        algorithm="HS256",
    )
    with pytest.raises(AuthenticationFailed):
        decode_access_token(incorrect_audience_token, settings)
