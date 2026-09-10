import hashlib
import logging
from functools import lru_cache
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.adapters.redis_rate_limiter import RedisRateLimiter
from app.adapters.smtp_email import SmtpConfiguration, SmtpEmailSender
from app.api.dependencies import get_current_principal
from app.core.config import Settings, get_settings
from app.core.security import create_access_token
from app.db.session import get_session
from app.domain.auth import (
    AuthenticatedUser,
    AuthenticationFailed,
    EmailAlreadyRegistered,
    Principal,
)
from app.repositories.sqlalchemy_auth_repository import SqlAlchemyAuthRepository
from app.services.access import is_application_admin
from app.services.auth import AuthService
from app.services.signup import SignupMailUnavailable, SignupService, SignupThrottled

router = APIRouter(prefix="/auth", tags=["authentication"])
logger = logging.getLogger(__name__)


class RegisterRequest(BaseModel):
    organization_name: str = Field(min_length=2, max_length=255)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

    @field_validator("organization_name")
    @classmethod
    def organization_name_cannot_be_blank(cls, value: str) -> str:
        normalized_value = value.strip()
        if len(normalized_value) < 2:
            raise ValueError("Organization name must contain at least two non-space characters")
        return normalized_value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class AuthenticatedUserResponse(BaseModel):
    id: str
    organization_id: str
    email: EmailStr
    role: str
    is_application_admin: bool = False


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int
    user: AuthenticatedUserResponse


class SignupChallengeResponse(BaseModel):
    challenge_id: UUID
    expires_in_seconds: int = 600
    resend_after_seconds: int = 60


class VerifySignupRequest(BaseModel):
    challenge_id: UUID
    code: str = Field(pattern=r"^[0-9]{6}$")


def _signup_service(session: Session) -> SignupService:
    settings = get_settings()
    return SignupService(
        session,
        SmtpEmailSender(SmtpConfiguration.from_settings(settings)),
        settings.jwt_secret.get_secret_value(),
    )


@router.post("/register", response_model=SignupChallengeResponse, status_code=202)
def register_owner(
    payload: RegisterRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> SignupChallengeResponse:
    settings = get_settings()
    settings.validate_runtime_security()
    _enforce_signup_ip_limit(request)
    try:
        pending = _signup_service(session).start(
            organization_name=payload.organization_name,
            email=str(payload.email),
            password=payload.password,
        )
        session.commit()
    except SignupThrottled:
        session.rollback()
        raise HTTPException(
            status_code=429,
            detail=(
                "Please wait before requesting another code. "
                "Maximum five codes or guesses per hour."
            ),
        ) from None
    except SignupMailUnavailable:
        session.rollback()
        raise HTTPException(
            status_code=503,
            detail=("We could not send the verification email. Please try again shortly."),
        ) from None
    except (EmailAlreadyRegistered, IntegrityError):
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email is already registered"
        ) from None
    except Exception:
        session.rollback()
        raise
    return SignupChallengeResponse(challenge_id=pending.id)


@router.post("/register/verify", response_model=TokenResponse, status_code=201)
def verify_signup(
    payload: VerifySignupRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> TokenResponse:
    settings = get_settings()
    settings.validate_runtime_security()
    _enforce_signup_ip_limit(request, verify=True)
    try:
        user = _signup_service(session).verify(payload.challenge_id, payload.code)
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=400, detail="Code is invalid or expired.") from None
    except Exception:
        session.rollback()
        raise
    if user is None:
        raise HTTPException(status_code=400, detail="Code is invalid, expired, or exhausted.")
    return _token_response(user, settings)


def _enforce_signup_ip_limit(request: Request, *, verify: bool = False) -> None:
    settings = get_settings()
    host = request.client.host if request.client else "unknown"
    key = hashlib.sha256(host.encode()).hexdigest()
    try:
        allowed = _rate_limiter(settings.redis_url, settings.dependency_timeout_seconds).allow(
            key=f"signup-ip:{verify}:{key}",
            limit=60 if verify else 20,
            window_seconds=3600,
        )
    except Exception:
        raise HTTPException(status_code=503, detail="Signup is temporarily unavailable.") from None
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many signup attempts. Try again later.")


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> TokenResponse:
    settings = get_settings()
    settings.validate_runtime_security()
    _enforce_auth_rate_limit(request=request, email=str(payload.email), action="login")
    service = AuthService(SqlAlchemyAuthRepository(session))
    try:
        user = service.authenticate(email=str(payload.email), password=payload.password)
        session.commit()
    except AuthenticationFailed:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except Exception:
        session.rollback()
        raise
    return _token_response(user, settings)


@router.get("/me", response_model=AuthenticatedUserResponse)
def current_user(
    principal: Annotated[Principal, Depends(get_current_principal)],
) -> AuthenticatedUserResponse:
    return AuthenticatedUserResponse(
        id=str(principal.user_id),
        organization_id=str(principal.org_id),
        email=principal.email,
        role=principal.role.value,
        is_application_admin=is_application_admin(principal.user_id),
    )


def _token_response(user: AuthenticatedUser, settings: Settings) -> TokenResponse:
    return TokenResponse(
        access_token=create_access_token(user, settings),
        expires_in_seconds=settings.jwt_access_token_minutes * 60,
        user=AuthenticatedUserResponse(
            id=str(user.id),
            organization_id=str(user.org_id),
            email=user.email,
            role=user.role.value,
            is_application_admin=is_application_admin(user.id),
        ),
    )


@lru_cache
def _rate_limiter(redis_url: str, timeout_seconds: float) -> RedisRateLimiter:
    return RedisRateLimiter(redis_url, timeout_seconds=timeout_seconds)


def _enforce_auth_rate_limit(*, request: Request, email: str, action: str) -> None:
    settings = get_settings()
    client_host = request.client.host if request.client else "unknown"
    identity = hashlib.sha256(f"{client_host}:{email.casefold()}".encode()).hexdigest()
    try:
        allowed = _rate_limiter(settings.redis_url, settings.dependency_timeout_seconds).allow(
            key=f"auth-rate:{action}:{identity}",
            limit=settings.auth_rate_limit_attempts,
            window_seconds=settings.auth_rate_limit_window_seconds,
        )
    except Exception:
        # Dependency readiness still fails, but an intermittent Redis issue must not lock
        # every customer out of the service.
        logger.warning("Authentication rate limiter is unavailable", exc_info=True)
        return
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Try again later.",
            headers={"Retry-After": str(settings.auth_rate_limit_window_seconds)},
        )
