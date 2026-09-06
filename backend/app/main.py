from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.alerts import router as alerts_router
from app.api.auth import router as auth_router
from app.api.billing import router as billing_router
from app.api.intelligence import router as intelligence_router
from app.api.organization import router as organization_router
from app.api.watchlist import router as watchlist_router
from app.core.config import get_settings
from app.core.observability import configure_logging, metrics_response, observe_request
from app.core.readiness import check_readiness
from app.db.session import get_session
from app.models.catalog import Product
from app.repositories.sqlalchemy_catalog_repository import SqlAlchemyCatalogRepository


@asynccontextmanager
async def lifespan(_: FastAPI):
    get_settings().validate_runtime_security()
    yield


settings = get_settings()
configure_logging(settings)
app = FastAPI(
    title="CVE Monitor API",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.api_docs_enabled else None,
    redoc_url=None,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.middleware("http")(observe_request)
app.include_router(auth_router)
app.include_router(alerts_router)
app.include_router(billing_router)
app.include_router(organization_router)
app.include_router(watchlist_router)
app.include_router(intelligence_router)


class ProductSearchResult(BaseModel):
    id: int
    vendor: str
    product_name: str
    version: str


@app.get("/healthz", tags=["operations"])
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz", tags=["operations"])
def readiness(session: Annotated[Session, Depends(get_session)]) -> dict[str, object]:
    result = check_readiness(session, get_settings())
    payload = {
        "status": "ready" if result.ready else "not_ready",
        "checks": {"database": result.database, "redis": result.redis},
    }
    if not result.ready:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=payload)
    return payload


@app.get("/metrics", tags=["operations"], include_in_schema=False)
def metrics() -> Response:
    return metrics_response()


@app.get("/catalog/products", response_model=list[ProductSearchResult], tags=["catalog"])
def search_products(
    query: Annotated[str, Query(alias="q", min_length=2, max_length=120)],
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> list[ProductSearchResult]:
    """Fuzzy product lookup for the future watchlist UI; CPE identifiers remain internal."""
    products = SqlAlchemyCatalogRepository(session).search(query, limit=limit)
    return [
        ProductSearchResult(
            id=product.id,
            vendor=product.vendor,
            product_name=product.product_name,
            version=product.cpe_version,
        )
        for product in products
    ]


@app.get("/catalog/vendors", response_model=list[ProductSearchResult], tags=["catalog"])
def search_vendors(
    query: Annotated[str, Query(alias="q", min_length=2, max_length=120)],
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> list[ProductSearchResult]:
    vendors = list(session.scalars(select(Product.vendor).distinct().where(
        Product.is_family.is_(True),
        func.lower(Product.vendor).contains(query.strip().casefold(), autoescape=True),
    ).order_by(Product.vendor).limit(limit)))
    rows = []
    for vendor in vendors:
        escaped = vendor.replace("\\", "\\\\").replace(":", "\\:")
        cpe_string = f"cpe:2.3:*:{escaped}:*:*:*:*:*:*:*:*:*"
        statement = insert(Product).values(
            part="*", vendor=vendor, product_name=f"All {vendor} products", cpe_product="*",
            cpe_version="*", cpe_string=cpe_string, is_family=False,
        ).on_conflict_do_nothing(index_elements=["cpe_string"])
        session.execute(statement)
        rows.append(session.scalar(select(Product).where(Product.cpe_string == cpe_string)))
    session.commit()
    return [ProductSearchResult(id=row.id, vendor=row.vendor,
                                product_name=row.product_name, version="*") for row in rows]
