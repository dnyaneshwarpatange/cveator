from datetime import UTC, datetime
from unittest.mock import Mock

from sqlalchemy.dialects import postgresql

from app.domain.cve import NormalizedCve
from app.models.cve import Cve
from app.repositories.sqlalchemy_cve_repository import SqlAlchemyCveRepository


def test_material_cve_update_reopens_matching_alerts_and_clears_stale_summary() -> None:
    previous_modified = datetime(2026, 9, 1, tzinfo=UTC)
    updated_modified = datetime(2026, 9, 5, tzinfo=UTC)
    cve = Cve(
        id=12,
        cve_id="CVE-2026-1000",
        source_json={"nvd": {"version": 1}},
        cvss_score=7.5,
        epss_score=0.1,
        is_kev=False,
        last_modified_at=previous_modified,
    )
    session = Mock()
    session.scalar.return_value = cve

    SqlAlchemyCveRepository(session).upsert_cve(
        NormalizedCve(
            cve_id=cve.cve_id,
            source="nvd",
            raw={"version": 2},
            cvss_score=9.8,
            last_modified_at=updated_modified,
        )
    )

    statement = session.execute.call_args.args[0]
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "UPDATE alerts" in sql
    assert "alerts.cve_id" in sql
    assert "plain_summary" in sql
    assert "sent_at" in sql
    assert "new" in statement.compile(dialect=postgresql.dialect()).params.values()


def test_epss_refresh_does_not_requeue_an_already_delivered_alert() -> None:
    cve = Cve(
        id=12,
        cve_id="CVE-2026-1000",
        source_json={"epss": {"score": 0.1}},
        cvss_score=7.5,
        epss_score=0.1,
        is_kev=False,
    )
    session = Mock()
    session.scalar.return_value = cve

    SqlAlchemyCveRepository(session).upsert_cve(
        NormalizedCve(
            cve_id=cve.cve_id,
            source="epss",
            raw={"score": 0.2},
            epss_score=0.2,
        )
    )

    session.execute.assert_not_called()
