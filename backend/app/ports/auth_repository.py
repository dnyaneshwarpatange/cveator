from typing import Protocol
from uuid import UUID

from app.domain.auth import AuthenticatedUser


class AuthRepository(Protocol):
    def get_by_email(self, email: str) -> AuthenticatedUser | None: ...

    def get_by_id(self, user_id: UUID) -> AuthenticatedUser | None: ...

    def create_organization_owner(
        self, *, organization_name: str, email: str, password_hash: str
    ) -> AuthenticatedUser: ...

    def create_member(
        self, *, org_id: UUID, email: str, password_hash: str, role: str
    ) -> AuthenticatedUser: ...

    def list_by_org(self, org_id: UUID) -> list[AuthenticatedUser]: ...

    def record_successful_login(self, user_id: UUID) -> None: ...
