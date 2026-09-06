from uuid import UUID

from app.core.security import hash_password, normalize_email, verify_dummy_password, verify_password
from app.domain.auth import (
    AuthenticatedUser,
    AuthenticationFailed,
    EmailAlreadyRegistered,
    OrganizationRole,
)
from app.ports.auth_repository import AuthRepository


class AuthService:
    def __init__(self, repository: AuthRepository) -> None:
        self._repository = repository

    def register_owner(
        self, *, organization_name: str, email: str, password: str
    ) -> AuthenticatedUser:
        normalized_email = normalize_email(email)
        if self._repository.get_by_email(normalized_email) is not None:
            raise EmailAlreadyRegistered
        return self._repository.create_organization_owner(
            organization_name=organization_name.strip(),
            email=normalized_email,
            password_hash=hash_password(password),
        )

    def authenticate(self, *, email: str, password: str) -> AuthenticatedUser:
        user = self._repository.get_by_email(normalize_email(email))
        if user is None:
            verify_dummy_password(password)
            raise AuthenticationFailed
        if not user.is_active or not verify_password(password, user.password_hash):
            raise AuthenticationFailed
        self._repository.record_successful_login(user.id)
        return user

    def register_member(
        self, *, org_id: UUID, email: str, password: str, role: OrganizationRole
    ) -> AuthenticatedUser:
        normalized_email = normalize_email(email)
        if self._repository.get_by_email(normalized_email) is not None:
            raise EmailAlreadyRegistered
        return self._repository.create_member(
            org_id=org_id,
            email=normalized_email,
            password_hash=hash_password(password),
            role=role.value,
        )

    def list_members(self, *, org_id: UUID) -> list[AuthenticatedUser]:
        return self._repository.list_by_org(org_id)
