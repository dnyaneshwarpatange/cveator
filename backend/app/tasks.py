from datetime import datetime, timedelta

from sqlalchemy import text

from app.adapters.cisa_kev import CisaKevFeed
from app.adapters.deterministic_summary import DeterministicSummaryGenerator
from app.adapters.epss import EpssCsvFeed
from app.adapters.mitre import MitreCveListFeed
from app.adapters.nvd import NvdCveFeed
from app.adapters.nvd_cpe import NvdCpeDictionaryFeed
from app.adapters.smtp_email import SmtpConfiguration, SmtpEmailSender
from app.core.config import get_settings
from app.core.time import utc_now
from app.db.session import SessionLocal, engine
from app.models.catalog_import import CatalogImport
from app.ports.cve_feed import CveFeed
from app.repositories.sqlalchemy_alert_repository import SqlAlchemyAlertRepository
from app.repositories.sqlalchemy_catalog_repository import SqlAlchemyCatalogRepository
from app.repositories.sqlalchemy_cve_repository import SqlAlchemyCveRepository
from app.repositories.sqlalchemy_notification_repository import SqlAlchemyNotificationRepository
from app.services.catalog import CatalogSyncSummary, ProductCatalogSyncService
from app.services.ingestion import CveIngestionService, SyncSummary
from app.services.matching import CveProductMatcher
from app.services.notification_composer import NotificationComposer
from app.services.notifications import NotificationDeliveryService
from app.services.summaries import AlertSummaryService
from app.worker import celery_app


def _initial_cursors() -> dict[str, datetime]:
    settings = get_settings()
    now = utc_now()
    # CVE List V5's public delta log is intentionally rolling. NVD is the durable history.
    return {
        "nvd": settings.nvd_initial_sync_start,
        "mitre": now - timedelta(days=30),
        "cisa_kev": now,
        "epss": now,
        "nvd_cpe_dictionary": settings.nvd_cpe_initial_sync_start,
    }


def _sync_feed(feed: CveFeed) -> SyncSummary:
    with SessionLocal.begin() as session:
        repository = SqlAlchemyCveRepository(session)
        service = CveIngestionService(repository, _initial_cursors())
        matcher = CveProductMatcher(repository)
        on_record_persisted = (
            matcher.match_record if feed.source_name in {"nvd", "mitre"} else None
        )
        summary = service.sync(feed, on_record_persisted=on_record_persisted)
        # Project the global product/CVE graph into tenant-visible alerts in the same
        # transaction. The unique constraint makes repeated incremental syncs safe.
        SqlAlchemyAlertRepository(session).create_missing_alerts()
        return summary


def _sync_catalog(feed: NvdCpeDictionaryFeed) -> CatalogSyncSummary:
    from sqlalchemy import text

    from app.db.session import engine
    from app.models.catalog_import import CatalogImport

    with SessionLocal() as session:
        progress = session.get(CatalogImport, feed.source_name)
        complete = progress is not None and progress.status == "complete"
    if not complete:
        # The dedicated bootstrap process owns the long initial import, keeping
        # the notification worker responsive on small single-worker deployments.
        with SessionLocal() as session:
            cursor = SqlAlchemyCatalogRepository(session).get_cursor(feed.source_name)
        return CatalogSyncSummary(
            feed.source_name, 0, cursor or _initial_cursors()[feed.source_name],
        )
    with engine.connect() as connection:
        if not connection.scalar(text("SELECT pg_try_advisory_lock(830425029)")):
            return CatalogSyncSummary(feed.source_name, 0, utc_now())
        try:
            with SessionLocal() as session:
                repository = SqlAlchemyCatalogRepository(session)
                service = ProductCatalogSyncService(repository, _initial_cursors())
                return service.sync_pages(feed, commit_page=session.commit)
        finally:
            connection.execute(text("SELECT pg_advisory_unlock(830425029)"))


@celery_app.task(name="app.tasks.sync_nvd")
def sync_nvd() -> dict[str, object]:
    with SessionLocal() as session:
        baseline = session.get(CatalogImport, "nvd_cves")
        if baseline is None or baseline.status != "complete":
            return {"source": "nvd", "status": "baseline_running"}
    with engine.connect() as connection:
        if not connection.scalar(text("SELECT pg_try_advisory_lock(830425030)")):
            return {"source": "nvd", "status": "baseline_running"}
        try:
            return _sync_nvd_pages()
        finally:
            connection.execute(text("SELECT pg_advisory_unlock(830425030)"))


def _sync_nvd_pages() -> dict[str, object]:
    settings = get_settings()
    api_key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None
    feed = NvdCveFeed(
        api_key=api_key,
        results_per_page=settings.nvd_results_per_page,
        request_interval_seconds=settings.nvd_rate_limit_interval_seconds,
    )
    try:
        with SessionLocal() as session:
            cursor = SqlAlchemyCveRepository(session).get_cursor("nvd")
        cursor = cursor or settings.nvd_initial_sync_start
        count = 0
        for page in feed.iter_pages(cursor):
            with SessionLocal.begin() as session:
                repository = SqlAlchemyCveRepository(session)
                matcher = CveProductMatcher(repository)
                for record in page.records:
                    if repository.upsert_cve(record) is not False:
                        matcher.match_record(record)
                repository.save_cursor("nvd", page.next_cursor)
                SqlAlchemyAlertRepository(session).create_missing_alerts()
            count += len(page.records)
            cursor = page.next_cursor
        return {"source": "nvd", "records_upserted": count, "high_watermark": cursor.isoformat()}
    finally:
        feed.close()


@celery_app.task(name="app.tasks.sync_mitre")
def sync_mitre() -> dict[str, object]:
    settings = get_settings()
    feed = MitreCveListFeed(delta_log_url=settings.mitre_delta_log_url)
    try:
        return _summary_to_dict(_sync_feed(feed))
    finally:
        feed.close()


@celery_app.task(name="app.tasks.sync_cisa_kev")
def sync_cisa_kev() -> dict[str, object]:
    settings = get_settings()
    feed = CisaKevFeed(url=settings.cisa_kev_url)
    try:
        return _summary_to_dict(_sync_feed(feed))
    finally:
        feed.close()


@celery_app.task(name="app.tasks.sync_epss")
def sync_epss() -> dict[str, object]:
    from app.services.epss_sync import sync_epss_feed

    settings = get_settings()
    feed = EpssCsvFeed(url=settings.epss_csv_url)
    try:
        return sync_epss_feed(feed)
    finally:
        feed.close()


@celery_app.task(name="app.tasks.sync_product_catalog")
def sync_product_catalog() -> dict[str, object]:
    settings = get_settings()
    api_key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None
    feed = NvdCpeDictionaryFeed(
        api_key=api_key,
        results_per_page=settings.nvd_cpe_results_per_page,
        request_interval_seconds=settings.nvd_rate_limit_interval_seconds,
    )
    try:
        summary = _sync_catalog(feed)
    finally:
        feed.close()
    rebuild_cve_product_matches.delay()
    return _catalog_summary_to_dict(summary)


@celery_app.task(name="app.tasks.rebuild_cve_product_matches")
def rebuild_cve_product_matches(batch_size: int = 500) -> dict[str, int]:
    """Durably request historical backfills for subscribed products only.

    Keep the former batch_size argument for already queued tasks. Database-side
    selection avoids materializing either the global catalog or the CVE archive.
    """
    from sqlalchemy import func, literal, select
    from sqlalchemy.dialects.postgresql import insert

    from app.models.catalog import WatchlistItem
    from app.models.product_sync import ProductSync

    subscribed = select(
        WatchlistItem.product_id, literal("pending"), literal(0), func.now()
    ).distinct()
    request = insert(ProductSync).from_select(
        ["product_id", "status", "records", "updated_at"], subscribed
    ).on_conflict_do_update(
        index_elements=[ProductSync.product_id],
        set_={"status": "pending", "records": 0, "error": None, "updated_at": func.now()},
        where=ProductSync.status != "running",
    ).returning(ProductSync.product_id)
    with SessionLocal.begin() as session:
        requested = len(list(session.scalars(request)))
    # Commit before dispatch: if dispatch fails, the periodic worker can still
    # recover these persisted requests without repeating the global scan.
    sync_watchlist_products.delay()
    return {"products_requested": requested}


@celery_app.task(name="app.tasks.sync_all_sources")
def sync_all_sources() -> list[dict[str, object]]:
    # Deliberately invoke synchronously inside one worker task to avoid overlapping cursors.
    summaries = []
    for source, sync in (("nvd", sync_nvd), ("mitre", sync_mitre), ("cisa_kev", sync_cisa_kev)):
        with SessionLocal.begin() as session:
            progress = session.get(CatalogImport, f"sync_{source}")
            if progress is None:
                progress = CatalogImport(source=f"sync_{source}", started_at=utc_now())
                session.add(progress)
            progress.status, progress.error, progress.updated_at = "running", None, utc_now()
        try:
            summary = sync()
            outcome = summary.get("status", "complete")
            error = None
        except Exception as exc:
            # An outage in one source must not stop every other provider refreshing.
            outcome = "failed"
            error = f"{source} update failed ({type(exc).__name__}); next scheduled run will retry."
            summary = {"source": source, "status": outcome, "error": error}
        with SessionLocal.begin() as session:
            progress = session.get(CatalogImport, f"sync_{source}")
            progress.status, progress.error, progress.updated_at = outcome, error, utc_now()
        summaries.append(summary)
    generate_alert_summaries.delay()
    send_realtime_alerts.delay()
    return summaries


@celery_app.task(name="app.tasks.sync_watchlist_products")
def sync_watchlist_products() -> dict:
    from app.services.product_backfill import sync_pending_products

    result = sync_pending_products()
    generate_alert_summaries.delay()
    return result


@celery_app.task(name="app.tasks.send_realtime_alerts")
def send_realtime_alerts() -> dict[str, int | bool]:
    return _deliver_notifications(realtime=True)


@celery_app.task(name="app.tasks.send_daily_digests")
def send_daily_digests() -> dict[str, int | bool]:
    return _deliver_notifications(realtime=False)


@celery_app.task(name="app.tasks.generate_alert_summaries")
def generate_alert_summaries() -> dict[str, int | bool]:
    settings = get_settings()
    summaries_generated = 0
    batches_processed = 0
    queue_truncated = False
    for _ in range(settings.notification_max_batches_per_run):
        with SessionLocal.begin() as session:
            service = AlertSummaryService(
                SqlAlchemyNotificationRepository(session),
                DeterministicSummaryGenerator(),
            )
            generated = service.generate_pending(limit=settings.notification_batch_limit)
        batches_processed += 1
        summaries_generated += generated
        if generated < settings.notification_batch_limit:
            break
    else:
        queue_truncated = True
    return {
        "enabled": True,
        "summaries_generated": summaries_generated,
        "batches_processed": batches_processed,
        "queue_truncated": queue_truncated,
    }


def _deliver_notifications(*, realtime: bool) -> dict[str, int | bool]:
    settings = get_settings()
    if not settings.email_delivery_enabled:
        return {"enabled": False}
    settings.validate_email_configuration()
    totals = {
        "alerts_found": 0,
        "alerts_marked_sent": 0,
        "emails_sent": 0,
        "emails_failed": 0,
        "organizations_without_recipients": 0,
    }
    batches_processed = 0
    queue_truncated = False
    for _ in range(settings.notification_max_batches_per_run):
        with SessionLocal.begin() as session:
            service = NotificationDeliveryService(
                SqlAlchemyNotificationRepository(session),
                SmtpEmailSender(SmtpConfiguration.from_settings(settings)),
                DeterministicSummaryGenerator(),
                NotificationComposer(public_app_url=settings.public_app_url),
            )
            result = (
                service.deliver_realtime(limit=settings.notification_batch_limit)
                if realtime
                else service.deliver_digest(limit=settings.notification_batch_limit)
            )
        batches_processed += 1
        for field in totals:
            totals[field] += getattr(result, field)
        if (
            result.alerts_found < settings.notification_batch_limit
            or result.alerts_marked_sent < result.alerts_found
        ):
            break
    else:
        queue_truncated = True
    return {
        "enabled": True,
        **totals,
        "batches_processed": batches_processed,
        "queue_truncated": queue_truncated,
    }


def _summary_to_dict(summary: SyncSummary) -> dict[str, object]:
    return {
        "source": summary.source,
        "records_upserted": summary.records_upserted,
        "high_watermark": summary.high_watermark.isoformat(),
    }


def _catalog_summary_to_dict(summary: CatalogSyncSummary) -> dict[str, object]:
    return {
        "source": summary.source,
        "products_upserted": summary.products_upserted,
        "high_watermark": summary.high_watermark.isoformat(),
    }
