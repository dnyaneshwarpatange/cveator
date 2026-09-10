from datetime import timedelta

from sqlalchemy import delete

from app.core.time import utc_now
from app.db.session import SessionLocal
from app.models.signup import PendingSignup
from app.worker import celery_app


@celery_app.task(name="app.signup_tasks.purge_pending_signups")
def purge_pending_signups():
    with SessionLocal.begin() as session:
        result = session.execute(
            delete(PendingSignup).where(
                PendingSignup.window_started_at < utc_now() - timedelta(hours=24)
            )
        )
        return result.rowcount
