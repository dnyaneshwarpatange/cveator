from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID


class OrganizationRole(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    id: UUID
    org_id: UUID
    email: str
    role: OrganizationRole
    password_hash: str
    token_version: int
    is_active: bool


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: UUID
    org_id: UUID
    email: str
    role: OrganizationRole
    token_version: int


class AuthenticationFailed(Exception):
    pass


class EmailAlreadyRegistered(Exception):
    pass
