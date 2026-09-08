from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import decode_access_token
from app.db.session import get_session
from app.domain.auth import AuthenticationFailed, OrganizationRole, Principal
from app.repositories.sqlalchemy_auth_repository import SqlAlchemyAuthRepository

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: Annotated[Session, Depends(get_session)],
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _credentials_exception()
    settings = get_settings()
    settings.validate_runtime_security()
    try:
        claimed_principal = decode_access_token(credentials.credentials, settings)
    except AuthenticationFailed:
        raise _credentials_exception() from None

    user = SqlAlchemyAuthRepository(session).get_by_id(claimed_principal.user_id)
    if (
        user is None
        or not user.is_active
        or user.org_id != claimed_principal.org_id
        or user.token_version != claimed_principal.token_version
    ):
        raise _credentials_exception()
    return Principal(
        user_id=user.id,
        org_id=user.org_id,
        email=user.email,
        role=user.role,
        token_version=user.token_version,
    )


def require_roles(*roles: OrganizationRole) -> Callable[[Principal], Principal]:
    def role_dependency(
        principal: Annotated[Principal, Depends(get_current_principal)],
    ) -> Principal:
        if principal.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return principal

    return role_dependency


def require_monitoring_access(
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> Principal:
    from app.services.access import monitoring_access

    if not monitoring_access(session, principal.org_id)["has_access"]:
        raise HTTPException(
            status_code=402,
            detail=("Your 3-day free trial has ended. Choose a paid plan in Plan & billing "
                    "to continue software monitoring."),
        )
    return principal


def _credentials_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
