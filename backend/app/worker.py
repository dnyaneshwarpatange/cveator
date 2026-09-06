from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings

settings = get_settings()
celery_app = Celery(
    "cve_monitor",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks"],
)
celery_app.conf.update(
    timezone="UTC",
    task_track_started=True,
    beat_schedule={
        "sync-subscribed-product-history": {
            "task": "app.tasks.sync_watchlist_products", "schedule": 60,
        },
        "sync-cve-sources": {
            "task": "app.tasks.sync_all_sources",
            "schedule": 30 * 60,
        },
        "sync-epss-daily": {
            "task": "app.tasks.sync_epss",
            "schedule": 24 * 60 * 60,
        },
        "sync-product-catalog-daily": {
            "task": "app.tasks.sync_product_catalog",
            "schedule": 24 * 60 * 60,
        },
        "send-realtime-security-alerts": {
            "task": "app.tasks.send_realtime_alerts",
            "schedule": 60,
        },
        "generate-plain-language-summaries": {
            "task": "app.tasks.generate_alert_summaries",
            "schedule": 60,
        },
        "send-daily-security-digests": {
            "task": "app.tasks.send_daily_digests",
            "schedule": crontab(
                hour=settings.digest_hour_utc,
                minute=settings.digest_minute_utc,
            ),
        },
    },
)
