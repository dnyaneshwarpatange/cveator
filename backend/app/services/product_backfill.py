"""Populate subscribed products from historical data without changing global cursors."""

from datetime import timedelta

from sqlalchemy import exists, or_, select, update

from app.adapters.nvd import NvdCveFeed
from app.core.config import get_settings
from app.core.time import utc_now
from app.db.session import SessionLocal
from app.domain.cve import NormalizedCve
from app.models.catalog import Product, WatchlistItem
from app.models.product_sync import ProductSync
from app.repositories.sqlalchemy_alert_repository import SqlAlchemyAlertRepository
from app.repositories.sqlalchemy_cve_repository import SqlAlchemyCveRepository
from app.services.matching import CveProductMatcher


def sync_pending_products(limit: int = 3) -> dict:
    settings = get_settings()
    cutoff = utc_now() - timedelta(minutes=30)
    with SessionLocal() as session:
        ids = list(session.scalars(select(ProductSync.product_id).where(or_(
            ProductSync.status == "pending",
            (ProductSync.status.in_(["failed", "running"])) & (ProductSync.updated_at < cutoff),
        )).order_by(ProductSync.updated_at).limit(limit)))
    results = []
    for product_id in ids:
        with SessionLocal.begin() as session:
            state = session.scalar(select(ProductSync).where(ProductSync.product_id == product_id)
                                   .with_for_update(skip_locked=True))
            if state is None or not (
                state.status == "pending"
                or (state.status in {"failed", "running"} and state.updated_at < cutoff)
            ):
                continue
            if not session.scalar(select(exists().where(WatchlistItem.product_id == product_id))):
                state.status, state.updated_at = "cancelled", utc_now()
                continue
            product = session.get(Product, product_id)
            if product is None:
                continue
            cpe = product.cpe_string
            state.status, state.error, state.records = "running", None, 0
            state.updated_at = utc_now()
        feed = NvdCveFeed(
            api_key=settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None,
            results_per_page=settings.nvd_results_per_page,
            request_interval_seconds=settings.nvd_rate_limit_interval_seconds,
        )
        count = 0
        try:
            for records in feed.iter_product(cpe):
                with SessionLocal.begin() as session:
                    repository = SqlAlchemyCveRepository(session, notify_changes=False)
                    matcher = CveProductMatcher(repository)
                    for record in records:
                        _match_historical_record(repository, matcher, record)
                    count += len(records)
                    session.execute(update(ProductSync).where(ProductSync.product_id == product_id)
                                    .values(records=count, updated_at=utc_now()))
                    SqlAlchemyAlertRepository(session).create_missing_alerts()
            with SessionLocal.begin() as session:
                session.execute(update(ProductSync).where(ProductSync.product_id == product_id)
                                .values(status="complete", records=count, updated_at=utc_now()))
            results.append({"product_id": product_id, "records": count, "status": "complete"})
        except Exception as exc:
            # Do not expose connection strings, API headers or request content in the UI.
            error = f"Historical import failed ({type(exc).__name__}); retry is scheduled."
            with SessionLocal.begin() as session:
                session.execute(update(ProductSync).where(ProductSync.product_id == product_id)
                                .values(status="failed", error=error, updated_at=utc_now()))
            results.append({"product_id": product_id, "status": "failed", "error": error})
        finally:
            feed.close()
    return {"products": results}


def _match_historical_record(repository, matcher, record: NormalizedCve) -> None:
    if repository.upsert_cve(record) is not False:
        matcher.match_record(record)
        return
    # A new subscription still needs matches even if the historical endpoint
    # returns an older revision. Never roll applicability back to that revision.
    current = repository.get_cve_source_payload(record.cve_id, "nvd")
    if current is not None:
        matcher.match_record(NormalizedCve(cve_id=record.cve_id, source="nvd", raw=current))
