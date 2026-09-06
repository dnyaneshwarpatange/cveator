"""Read-only shared vulnerability intelligence, authenticated through the app."""

import logging
import re
from threading import Lock, Thread
from time import monotonic
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import column, exists, func, literal, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session, defer

from app.adapters.intelligence_counts_cache import read_counts, write_counts
from app.api.dependencies import get_current_principal
from app.core.time import utc_now
from app.db.session import SessionLocal, get_session
from app.domain.auth import Principal
from app.domain.cve_history import aggregate_cve_sources
from app.models.catalog import Product, WatchlistItem
from app.models.catalog_import import CatalogImport
from app.models.cve import Cve, CveChange, IngestionCursor
from app.models.product_sync import ProductSync

router = APIRouter(prefix="/intelligence", tags=["intelligence"])
PrincipalDependency = Annotated[Principal, Depends(get_current_principal)]
SessionDependency = Annotated[Session, Depends(get_session)]
_counts_lock = Lock()
_counts_cache: tuple[float, dict] = (0, {})
_counts_refreshing = False


def _database_counts(session: Session) -> dict:
    # Counts are global/public data, never tenant data. Avoid multiple dashboards
    # scanning the million-entry dictionary concurrently during a cold import.
    global _counts_cache, _counts_refreshing
    with _counts_lock:
        expires_at, counts = _counts_cache
        if not counts:
            counts = read_counts()
            if counts:
                _counts_cache = (0, counts)
        if counts:
            if monotonic() >= expires_at and not _counts_refreshing:
                _counts_refreshing = True
                Thread(target=_refresh_counts, daemon=True).start()
            return counts
        counts = _query_counts(session)
        _counts_cache = (monotonic() + 60, counts)
        write_counts(counts)
        return counts


def _query_counts(session: Session) -> dict:
    return {
        "cves": session.scalar(select(func.count(Cve.id))
                               .where(~Cve.cve_id.like("CVE-DEMO%"))),
        "products": session.scalar(select(func.count(Product.id))),
        "product_families": session.scalar(select(func.count(Product.id))
                                           .where(Product.is_family.is_(True))),
        "counts_updated_at": utc_now().isoformat(),
    }


def _refresh_counts() -> None:
    global _counts_cache, _counts_refreshing
    try:
        with SessionLocal() as session:
            counts = _query_counts(session)
        write_counts(counts)
        with _counts_lock:
            _counts_cache = (monotonic() + 60, counts)
    except Exception as exc:
        logging.getLogger(__name__).warning("Count refresh failed: %s", type(exc).__name__)
        with _counts_lock:
            _counts_cache = (monotonic() + 60, _counts_cache[1])
    finally:
        with _counts_lock:
            _counts_refreshing = False


@router.get("/status")
def data_status(principal: PrincipalDependency, session: SessionDependency) -> dict:
    imports = list(session.scalars(select(CatalogImport).order_by(CatalogImport.source)))
    catalog = next((item for item in imports if item.source == "nvd_cpe_dictionary"), None)
    sources = session.scalars(select(IngestionCursor).order_by(IngestionCursor.source))
    syncs = session.scalars(
        select(ProductSync).join(WatchlistItem, WatchlistItem.product_id == ProductSync.product_id)
        .where(WatchlistItem.org_id == principal.org_id)
    )
    return {
        **_database_counts(session),
        "catalog": _import_status(catalog),
        "imports": [{"source": item.source, **_import_status(item)} for item in imports],
        "sources": [{"source": row.source, "high_watermark": row.high_watermark,
                     "updated_at": row.updated_at} for row in sources],
        "product_syncs": [{"product_id": row.product_id, "status": row.status,
                           "records": row.records, "updated_at": row.updated_at,
                           "error": row.error} for row in syncs],
    }


def _import_status(item: CatalogImport | None) -> dict:
    return {
        "status": item.status if item else "not_started",
        "processed": item.next_start_index if item else 0,
        "total": item.total_results if item and item.total_results else None,
        "updated_at": item.updated_at if item else None,
        "error": item.error if item else None,
    }


@router.get("/cves")
def browse_cves(
    principal: PrincipalDependency,
    session: SessionDependency,
    q: Annotated[str, Query(max_length=120)] = "",
    vendor: Annotated[str, Query(max_length=255)] = "",
    product: Annotated[str, Query(max_length=255)] = "",
    kev: bool | None = None,
    min_cvss: Annotated[float | None, Query(ge=0, le=10)] = None,
    min_epss: Annotated[float | None, Query(ge=0, le=1)] = None,
    page: Annotated[int, Query(ge=1, le=10000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
) -> dict:
    filters = [~Cve.cve_id.like("CVE-DEMO%")]
    if q.strip():
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", q.strip(), re.IGNORECASE):
            filters.append(Cve.cve_id == q.strip().upper())
        else:
            filters.append(Cve.normalized_json["description"].astext.ilike(
                f"%{_escape(q.strip())}%", escape="\\"
            ))
    if vendor.strip() or product.strip():
        affected = func.jsonb_array_elements(
            func.coalesce(Cve.normalized_json["products"], literal([], type_=JSONB))
        ).table_valued(column("value", JSONB))
        identity_filters = []
        for field, value in (("vendor", vendor), ("product", product)):
            if value.strip():
                if re.fullmatch(r"[\w .+-]+", value.strip(), re.ASCII):
                    # Indexed broad prefilter; the EXISTS below still enforces
                    # vendor and product on the same structured identity.
                    filters.append(Cve.normalized_json["products"].astext.ilike(
                        f"%{_escape(value.strip())}%", escape="\\",
                    ))
                identity_filters.append(affected.c.value[field].astext.ilike(
                    f"%{_escape(value.strip())}%", escape="\\"
                ))
        filters.append(exists(select(1).select_from(affected).where(*identity_filters)))
    if kev is not None:
        filters.append(Cve.is_kev.is_(kev))
    if min_cvss is not None:
        filters.append(Cve.cvss_score >= min_cvss)
    if min_epss is not None:
        filters.append(Cve.epss_score >= min_epss)
    total = (_database_counts(session)["cves"] if len(filters) == 1 else
             session.scalar(select(func.count(Cve.id)).where(*filters))) or 0
    rows = session.scalars(select(Cve).options(defer(Cve.source_json)).where(*filters)
                           .order_by(Cve.last_modified_at.desc().nullslast(), Cve.id.desc())
                           .offset((page - 1) * page_size).limit(page_size))
    return {"items": [_cve_item(row) for row in rows], "total": total,
            "page": page, "page_size": page_size}


@router.get("/cves/{cve_id}")
def cve_detail(cve_id: str, principal: PrincipalDependency, session: SessionDependency) -> dict:
    cve = session.scalar(select(Cve).where(Cve.cve_id == cve_id.upper()))
    if cve is None:
        raise HTTPException(status_code=404, detail="CVE has not been imported yet")
    history = session.scalars(
        select(CveChange).where(CveChange.cve_id == cve.id)
        .order_by(CveChange.observed_at.desc(), CveChange.id.desc()).limit(100)
    )
    return {**_cve_item(cve), "sources": sorted(cve.source_json),
            "normalized": cve.normalized_json or aggregate_cve_sources(cve.source_json),
            "history": [{"id": row.id, "source": row.source, "kind": row.kind,
                         "changes": row.changes, "observed_at": row.observed_at,
                         "source_modified_at": row.source_modified_at} for row in history]}


def _cve_item(cve: Cve) -> dict:
    normalized = cve.normalized_json or aggregate_cve_sources(cve.source_json)
    products = normalized.get("products", [])
    return {
        "cve_id": cve.cve_id, "description": normalized.get("description") or "",
        "cvss_score": cve.cvss_score, "epss_score": cve.epss_score, "is_kev": cve.is_kev,
        "published_at": cve.published_at, "last_modified_at": cve.last_modified_at,
        "vendors": sorted({item["vendor"] for item in products if item.get("vendor")}),
        "products": sorted({item["product"] for item in products if item.get("product")}),
    }


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
