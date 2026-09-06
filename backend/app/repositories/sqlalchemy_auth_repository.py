from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.domain.auth import AuthenticatedUser, OrganizationRole
from app.models.catalog import Organization, User


class SqlAlchemyAuthRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_email(self, email: str) -> AuthenticatedUser | None:
        user = self._session.scalar(select(User).where(func.lower(User.email) == email))
        return _to_authenticated_user(user) if user is not None else None

    def get_by_id(self, user_id: UUID) -> AuthenticatedUser | None:
        user = self._session.scalar(select(User).where(User.id == user_id))
        return _to_authenticated_user(user) if user is not None else None

    def create_organization_owner(
        self, *, organization_name: str, email: str, password_hash: str
    ) -> AuthenticatedUser:
        org_id = uuid4()
        user_id = uuid4()
        self._session.add(Organization(id=org_id, name=organization_name))
        self._session.add(
            User(
                id=user_id,
                org_id=org_id,
                email=email,
                password_hash=password_hash,
                role=OrganizationRole.OWNER.value,
            )
        )
        return AuthenticatedUser(
            id=user_id,
            org_id=org_id,
            email=email,
            role=OrganizationRole.OWNER,
            password_hash=password_hash,
            token_version=0,
            is_active=True,
        )

    def record_successful_login(self, user_id: UUID) -> None:
        self._session.execute(
            User.__table__.update().where(User.id == user_id).values(last_login_at=utc_now())
        )

    def create_member(
        self, *, org_id: UUID, email: str, password_hash: str, role: str
    ) -> AuthenticatedUser:
        user_id = uuid4()
        self._session.add(
            User(
                id=user_id,
                org_id=org_id,
                email=email,
                password_hash=password_hash,
                role=role,
            )
        )
        return AuthenticatedUser(
            id=user_id,
            org_id=org_id,
            email=email,
            role=OrganizationRole(role),
            password_hash=password_hash,
            token_version=0,
            is_active=True,
        )

    def list_by_org(self, org_id: UUID) -> list[AuthenticatedUser]:
        statement = select(User).where(User.org_id == org_id).order_by(User.created_at, User.email)
        return [_to_authenticated_user(user) for user in self._session.scalars(statement)]


def _to_authenticated_user(user: User) -> AuthenticatedUser:
    return AuthenticatedUser(
        id=user.id,
        org_id=user.org_id,
        email=user.email,
        role=OrganizationRole(user.role),
        password_hash=user.password_hash,
        token_version=user.token_version,
        is_active=user.is_active,
    )
