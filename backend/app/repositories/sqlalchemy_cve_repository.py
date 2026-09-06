from datetime import datetime

from sqlalchemy import delete, exists, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.time import parse_upstream_datetime
from app.domain.alerts import AlertStatus
from app.domain.cve import NormalizedCve, ProductCandidate
from app.domain.cve_history import aggregate_cve_sources, meaningful_changes
from app.models.catalog import Alert, CveProductMatch, Product, WatchlistItem
from app.models.cve import Cve, CveChange, IngestionCursor


class SqlAlchemyCveRepository:
    """Persistence adapter. It preserves each upstream's raw record under a source key."""

    def __init__(self, session: Session, *, notify_changes: bool = True) -> None:
        self._session = session
        self._notify_changes = notify_changes

    def get_cursor(self, source: str) -> datetime | None:
        return self._session.scalar(
            select(IngestionCursor.high_watermark).where(IngestionCursor.source == source)
        )

    def save_cursor(self, source: str, high_watermark: datetime) -> None:
        cursor = self._session.scalar(
            select(IngestionCursor).where(IngestionCursor.source == source)
        )
        if cursor is None:
            self._session.add(IngestionCursor(source=source, high_watermark=high_watermark))
        else:
            cursor.high_watermark = high_watermark

    def upsert_cve(self, record: NormalizedCve) -> bool:
        cve = self._session.scalar(select(Cve).where(Cve.cve_id == record.cve_id).with_for_update())
        is_existing = cve is not None
        if cve is None:
            cve = Cve(cve_id=record.cve_id, source_json={}, is_kev=False)
            self._session.add(cve)

        source_json = dict(cve.source_json)
        previous_modified = _source_modified(record.source, source_json.get(record.source, {}))
        if (
            previous_modified is not None
            and record.last_modified_at is not None
            and record.last_modified_at < previous_modified
        ):
            return False
        previous = self._snapshot(cve)
        source_json[record.source] = record.raw
        cve.source_json = source_json

        if record.is_kev is not None:
            cve.is_kev = record.is_kev
        if record.epss_score is not None:
            cve.epss_score = record.epss_score

        projection = aggregate_cve_sources(source_json)
        if projection["cvss_score"] is not None:
            cve.cvss_score = projection["cvss_score"]
        elif record.source in {"nvd", "mitre"}:
            # A current source can remove a score; do not retain a stale numeric value.
            cve.cvss_score = record.cvss_score
        if record.published_at is not None:
            cve.published_at = _earliest(cve.published_at, record.published_at)
        if record.last_modified_at is not None:
            cve.last_modified_at = _latest(cve.last_modified_at, record.last_modified_at)

        projection.update(
            cvss_score=cve.cvss_score, epss_score=cve.epss_score, is_kev=bool(cve.is_kev)
        )
        cve.normalized_json = projection
        changes = meaningful_changes(previous if is_existing else {}, projection)
        if changes:
            self._session.flush()
            self._session.add(
                CveChange(
                    cve_id=cve.id,
                    source=record.source,
                    kind="updated" if is_existing else "created",
                    changes=changes,
                    source_modified_at=record.last_modified_at,
                )
            )
        if is_existing and set(changes) - {"epss_score"}:
            values = {
                "plain_summary": None,
                "summary_provider": None,
                "summary_generated_at": None,
            }
            if self._notify_changes:
                values.update(status=AlertStatus.NEW.value, sent_at=None)
            self._session.execute(update(Alert).where(Alert.cve_id == cve.id).values(**values))
        return True

    @staticmethod
    def _snapshot(cve: Cve) -> dict:
        projection = dict(cve.normalized_json or aggregate_cve_sources(cve.source_json))
        projection.update(
            cvss_score=cve.cvss_score, epss_score=cve.epss_score, is_kev=bool(cve.is_kev)
        )
        return projection

    def reconcile_kev(self, active_cve_ids: set[str]) -> None:
        statement = select(Cve).where(Cve.is_kev.is_(True)).with_for_update()
        if active_cve_ids:
            statement = statement.where(Cve.cve_id.not_in(active_cve_ids))
        for cve in self._session.scalars(statement):
            previous = self._snapshot(cve)
            cve.is_kev = False
            cve.normalized_json = {**previous, "is_kev": False}
            self._session.add(
                CveChange(
                    cve_id=cve.id,
                    source="cisa_kev",
                    kind="updated",
                    changes={"is_kev": {"old": True, "new": False}},
                )
            )
            self._session.execute(
                update(Alert)
                .where(Alert.cve_id == cve.id)
                .values(
                    plain_summary=None,
                    summary_provider=None,
                    summary_generated_at=None,
                )
            )

    def find_product_candidates(
        self, *, part: str, vendor: str, product: str
    ) -> list[ProductCandidate]:
        statement = select(Product.id, Product.cpe_string).where(
            exists(select(WatchlistItem.id).where(WatchlistItem.product_id == Product.id))
        )
        if part != "*":
            statement = statement.where(or_(Product.part == part, Product.part == "*"))
        if vendor != "*":
            statement = statement.where(Product.vendor == vendor)
        if product != "*":
            statement = statement.where(
                or_(Product.cpe_product == product, Product.cpe_product == "*")
            )
        return [
            ProductCandidate(id=row.id, cpe_string=row.cpe_string)
            for row in self._session.execute(statement)
        ]

    def find_family_candidates(self, *, vendor: str, product: str) -> list[ProductCandidate]:
        def canonical(column):
            return func.regexp_replace(func.lower(column), r"[\s_]+", "_", "g")

        statement = select(Product.id, Product.cpe_string).where(
            exists(select(WatchlistItem.id).where(WatchlistItem.product_id == Product.id)),
            Product.cpe_version == "*",
            or_(Product.is_family.is_(True), Product.cpe_product == "*"),
            canonical(Product.vendor) == vendor,
            or_(canonical(Product.cpe_product) == product, Product.cpe_product == "*"),
        )
        return [
            ProductCandidate(id=row.id, cpe_string=row.cpe_string)
            for row in self._session.execute(statement)
        ]

    def get_cve_source_payload(self, cve_id: str, source: str) -> dict | None:
        self._session.flush()
        return self._session.scalar(
            select(Cve.source_json[source]).where(Cve.cve_id == cve_id)
        )

    def create_cve_product_matches(self, cve_id: str, product_ids: set[int]) -> int:
        # SessionLocal intentionally disables implicit autoflush. A just-ingested NVD CVE has
        # no database primary key until this point, so flush before resolving its FK.
        self._session.flush()
        database_cve_id = self._session.scalar(select(Cve.id).where(Cve.cve_id == cve_id))
        if database_cve_id is None or not product_ids:
            return 0
        statement = insert(CveProductMatch).values(
            [{"cve_id": database_cve_id, "product_id": product_id} for product_id in product_ids]
        )
        statement = statement.on_conflict_do_nothing(
            constraint="uq_cve_product_matches_cve_product"
        )
        result = self._session.execute(statement)
        return max(result.rowcount or 0, 0)

    def reconcile_cve_product_matches(self, cve_id: str, product_ids: set[int]) -> int:
        """Refresh current applicability while preserving historical tenant alerts."""
        self._session.flush()
        database_cve_id = self._session.scalar(select(Cve.id).where(Cve.cve_id == cve_id))
        if database_cve_id is None:
            return 0
        stale = delete(CveProductMatch).where(CveProductMatch.cve_id == database_cve_id)
        if product_ids:
            stale = stale.where(CveProductMatch.product_id.not_in(product_ids))
        self._session.execute(stale)
        return self.create_cve_product_matches(cve_id, product_ids)


def _earliest(current: datetime | None, candidate: datetime) -> datetime:
    return candidate if current is None or candidate < current else current


def _latest(current: datetime | None, candidate: datetime) -> datetime:
    return candidate if current is None or candidate > current else current


def _source_modified(source: str, raw: dict) -> datetime | None:
    if source == "nvd":
        return parse_upstream_datetime(raw.get("cve", raw).get("lastModified"))
    if source == "mitre":
        return parse_upstream_datetime(raw.get("cveMetadata", {}).get("dateUpdated"))
    return None
