from datetime import timedelta
from uuid import UUID, uuid4

import jwt
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash

from app.core.config import Settings
from app.core.time import utc_now
from app.domain.auth import AuthenticatedUser, AuthenticationFailed, OrganizationRole, Principal

_password_hasher = PasswordHash.recommended()
_dummy_password_hash = _password_hasher.hash("not-a-real-user-password")
_jwt_algorithm = "HS256"


def normalize_email(email: str) -> str:
    return email.strip().casefold()


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _password_hasher.verify(password, password_hash)
    except Exception:
        # A malformed stored hash is an authentication failure, never an HTTP 500.
        return False


def verify_dummy_password(password: str) -> None:
    """Keep unknown-email logins near the cost of a real password verification."""
    verify_password(password, _dummy_password_hash)


def create_access_token(user: AuthenticatedUser, settings: Settings) -> str:
    now = utc_now()
    expires_at = now + timedelta(minutes=settings.jwt_access_token_minutes)
    payload = {
        "sub": str(user.id),
        "org_id": str(user.org_id),
        "email": user.email,
        "role": user.role.value,
        "ver": user.token_version,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "nbf": now,
        "exp": expires_at,
        "jti": str(uuid4()),
    }
    return jwt.encode(payload, settings.jwt_secret.get_secret_value(), algorithm=_jwt_algorithm)


def decode_access_token(token: str, settings: Settings) -> Principal:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[_jwt_algorithm],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={
                "require": [
                    "sub",
                    "org_id",
                    "email",
                    "role",
                    "ver",
                    "iss",
                    "aud",
                    "iat",
                    "nbf",
                    "exp",
                ],
            },
        )
        return Principal(
            user_id=UUID(payload["sub"]),
            org_id=UUID(payload["org_id"]),
            email=str(payload["email"]),
            role=OrganizationRole(payload["role"]),
            token_version=int(payload["ver"]),
        )
    except (InvalidTokenError, KeyError, TypeError, ValueError) as error:
        raise AuthenticationFailed from error
