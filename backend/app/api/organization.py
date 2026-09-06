from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies import require_roles
from app.db.session import get_session
from app.domain.auth import AuthenticatedUser, EmailAlreadyRegistered, OrganizationRole, Principal
from app.repositories.sqlalchemy_auth_repository import SqlAlchemyAuthRepository
from app.services.auth import AuthService

router = APIRouter(prefix="/organization", tags=["organization"])
_organization_managers = require_roles(OrganizationRole.OWNER, OrganizationRole.ADMIN)


class MemberResponse(BaseModel):
    id: str
    email: EmailStr
    role: OrganizationRole


class CreateMemberRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    role: OrganizationRole = OrganizationRole.MEMBER


@router.get("/users", response_model=list[MemberResponse])
def list_members(
    principal: Annotated[Principal, Depends(_organization_managers)],
    session: Annotated[Session, Depends(get_session)],
) -> list[MemberResponse]:
    users = AuthService(SqlAlchemyAuthRepository(session)).list_members(org_id=principal.org_id)
    return [_member_response(user) for user in users]


@router.post("/users", response_model=MemberResponse, status_code=status.HTTP_201_CREATED)
def create_member(
    payload: CreateMemberRequest,
    principal: Annotated[Principal, Depends(_organization_managers)],
    session: Annotated[Session, Depends(get_session)],
) -> MemberResponse:
    if principal.role is OrganizationRole.ADMIN and payload.role in {
        OrganizationRole.OWNER,
        OrganizationRole.ADMIN,
    }:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")

    service = AuthService(SqlAlchemyAuthRepository(session))
    try:
        user = service.register_member(
            org_id=principal.org_id,
            email=str(payload.email),
            password=payload.password,
            role=payload.role,
        )
        session.commit()
    except (EmailAlreadyRegistered, IntegrityError):
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email is already registered"
        ) from None
    except Exception:
        session.rollback()
        raise
    return _member_response(user)


def _member_response(user: AuthenticatedUser) -> MemberResponse:
    return MemberResponse(id=str(user.id), email=user.email, role=user.role)
