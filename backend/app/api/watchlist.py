from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_principal, require_roles
from app.core.time import utc_now
from app.db.session import get_session
from app.domain.auth import OrganizationRole, Principal
from app.domain.watchlist import WatchlistProduct
from app.models.product_sync import ProductSync
from app.repositories.sqlalchemy_alert_repository import SqlAlchemyAlertRepository
from app.repositories.sqlalchemy_watchlist_repository import SqlAlchemyWatchlistRepository

router = APIRouter(prefix="/watchlist", tags=["watchlist"])


class WatchlistProductResponse(BaseModel):
    id: int
    vendor: str
    product_name: str
    version: str


class AddWatchlistItemRequest(BaseModel):
    product_id: int = Field(gt=0)


@router.get("", response_model=list[WatchlistProductResponse])
def list_watchlist(
    principal: Annotated[Principal, Depends(get_current_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> list[WatchlistProductResponse]:
    repository = SqlAlchemyWatchlistRepository(session, org_id=principal.org_id)
    return [_product_response(product) for product in repository.list_products()]


@router.post("", response_model=WatchlistProductResponse, status_code=status.HTTP_201_CREATED)
def add_watchlist_item(
    payload: AddWatchlistItemRequest,
    principal: Annotated[
        Principal,
        Depends(
            require_roles(
                OrganizationRole.OWNER,
                OrganizationRole.ADMIN,
                OrganizationRole.MEMBER,
            )
        ),
    ],
    session: Annotated[Session, Depends(get_session)],
) -> WatchlistProductResponse:
    repository = SqlAlchemyWatchlistRepository(session, org_id=principal.org_id)
    try:
        product = repository.add_product(payload.product_id)
        if product is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")
        SqlAlchemyAlertRepository(session).create_missing_alerts(org_id=principal.org_id)
        session.execute(insert(ProductSync).values(product_id=payload.product_id, status="pending")
                        .on_conflict_do_update(
                            index_elements=["product_id"],
                            set_={"status": "pending", "error": None, "updated_at": utc_now()},
                            where=ProductSync.status.in_(["cancelled", "failed"]),
                        ))
        session.commit()
    except HTTPException:
        session.rollback()
        raise
    except Exception:
        session.rollback()
        raise
    return _product_response(product)


@router.delete("/{product_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_watchlist_item(
    product_id: int,
    principal: Annotated[
        Principal,
        Depends(
            require_roles(
                OrganizationRole.OWNER,
                OrganizationRole.ADMIN,
                OrganizationRole.MEMBER,
            )
        ),
    ],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    repository = SqlAlchemyWatchlistRepository(session, org_id=principal.org_id)
    try:
        removed = repository.remove_product(product_id)
        session.commit()
    except Exception:
        session.rollback()
        raise
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Watchlist item not found"
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _product_response(product: WatchlistProduct) -> WatchlistProductResponse:
    return WatchlistProductResponse(
        id=product.id,
        vendor=product.vendor,
        product_name=product.product_name,
        version=product.version,
    )
