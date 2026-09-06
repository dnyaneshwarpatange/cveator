"""Batch updates for the complete daily FIRST probability dataset."""

from itertools import batched

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert

from app.adapters.epss import EpssCsvFeed
from app.core.time import utc_now
from app.db.session import SessionLocal, engine
from app.models.cve import Cve, CveChange
from app.repositories.sqlalchemy_cve_repository import SqlAlchemyCveRepository


def sync_epss_feed(feed: EpssCsvFeed) -> dict:
    updated = 0
    with engine.connect() as connection:
        if not connection.scalar(text("SELECT pg_try_advisory_lock(830425031)")):
            return {"source": "epss", "status": "already_running"}
        try:
            for batch in batched(feed.iter_records(), 500):
                with SessionLocal.begin() as session:
                    by_id = {record.cve_id: record for record in batch}
                    existing = session.execute(select(
                        Cve.id, Cve.cve_id, Cve.epss_score,
                        Cve.source_json["epss"]["date"].astext,
                    ).where(Cve.cve_id.in_(by_id)).order_by(Cve.id).with_for_update()).all()
                    values, history = [], []
                    for database_id, cve_id, old_score, old_date in existing:
                        record = by_id[cve_id]
                        new_date = record.raw.get("date")
                        if old_date and (not new_date or new_date < old_date):
                            continue
                        if old_score == record.epss_score and old_date == new_date:
                            continue
                        values.append({"cve_id": cve_id, "epss_score": record.epss_score,
                                       "source_json": {"epss": record.raw},
                                       "normalized_json": {"epss_score": record.epss_score}})
                        if old_score != record.epss_score:
                            history.append({
                                "cve_id": database_id, "source": "epss", "kind": "updated",
                                "changes": {"epss_score": {
                                    "old": old_score, "new": record.epss_score,
                                }},
                            })
                    if values:
                        statement = insert(Cve).values(values)
                        session.execute(statement.on_conflict_do_update(
                            index_elements=[Cve.cve_id], set_={
                                "epss_score": statement.excluded.epss_score,
                                "source_json": Cve.source_json.op("||")(
                                    statement.excluded.source_json),
                                "normalized_json": Cve.normalized_json.op("||")(
                                    statement.excluded.normalized_json),
                                "updated_at": utc_now(),
                            },
                        ))
                        if history:
                            session.execute(insert(CveChange).values(history))
                        updated += len(values)
            now = utc_now()
            with SessionLocal.begin() as session:
                SqlAlchemyCveRepository(session).save_cursor("epss", now)
            return {
                "source": "epss", "records_upserted": updated, "high_watermark": now.isoformat()
            }
        finally:
            connection.execute(text("SELECT pg_advisory_unlock(830425031)"))
