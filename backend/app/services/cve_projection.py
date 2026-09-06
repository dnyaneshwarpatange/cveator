"""Build source-aware views for historical data without creating artificial alerts."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.cve_history import aggregate_cve_sources
from app.models.cve import Cve


def backfill_cve_projections(session: Session, *, batch_size: int = 500) -> int:
    """Initialize missing projections in bounded batches; caller owns the transaction.

    This intentionally creates no change-history events and does not reopen alerts:
    old upstream records are the baseline, not updates that just happened now.
    """
    after_id = 0
    count = 0
    while True:
        rows = session.scalars(
            select(Cve)
            .where(
                Cve.id > after_id,
                Cve.normalized_json == {},
            )
            .order_by(Cve.id)
            .limit(batch_size)
            .with_for_update()
        ).all()
        if not rows:
            return count
        for cve in rows:
            projection = aggregate_cve_sources(cve.source_json)
            if projection["cvss_score"] is not None:
                cve.cvss_score = projection["cvss_score"]
            projection.update(
                cvss_score=cve.cvss_score,
                epss_score=cve.epss_score,
                is_kev=bool(cve.is_kev),
            )
            cve.normalized_json = projection
            count += 1
        after_id = rows[-1].id
        session.flush()
