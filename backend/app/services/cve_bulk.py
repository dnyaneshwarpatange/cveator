"""Transactional baseline CVE persistence without notifying historical matches."""

from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.domain.cve import NormalizedCve
from app.domain.cve_history import aggregate_cve_sources
from app.models.cve import Cve
from app.repositories.sqlalchemy_cve_repository import SqlAlchemyCveRepository


def import_cve_batch(session: Session, records: Iterable[NormalizedCve]) -> int:
    """Insert fresh records in one batch; preserve source merges on existing rows.

    Replaying an interrupted year's changed feed starts at record zero. A single
    prefetch skips identical records without individual database round trips.
    """
    by_id = {record.cve_id: record for record in records}
    if not by_id:
        return 0
    existing = dict(
        session.execute(select(Cve.cve_id, Cve.source_json).where(Cve.cve_id.in_(by_id))).all()
    )
    new_rows = []
    for record in by_id.values():
        if record.cve_id in existing:
            continue
        projection = aggregate_cve_sources({record.source: record.raw})
        projection.update(
            cvss_score=projection["cvss_score"]
            if projection["cvss_score"] is not None
            else record.cvss_score,
            epss_score=record.epss_score,
            is_kev=bool(record.is_kev),
        )
        new_rows.append(
            {
                "cve_id": record.cve_id,
                "source_json": {record.source: record.raw},
                "normalized_json": projection,
                "cvss_score": projection["cvss_score"],
                "epss_score": record.epss_score,
                "is_kev": bool(record.is_kev),
                "published_at": record.published_at,
                "last_modified_at": record.last_modified_at,
            }
        )
    inserted_ids: set[str] = set()
    if new_rows:
        inserted_ids = set(
            session.scalars(
                insert(Cve)
                .values(new_rows)
                .on_conflict_do_nothing(index_elements=[Cve.cve_id])
                .returning(Cve.cve_id)
            )
        )
    repository = SqlAlchemyCveRepository(session, notify_changes=False)
    for record in by_id.values():
        if record.cve_id in inserted_ids:
            continue
        if existing.get(record.cve_id, {}).get(record.source) == record.raw:
            continue
        # Concurrent inserts are merged here too; newer records are guarded in the repository.
        repository.upsert_cve(record)
    return len(by_id)
