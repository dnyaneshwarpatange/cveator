from unittest.mock import Mock

import pytest
from sqlalchemy.dialects import postgresql

from app.api.intelligence import browse_cves


@pytest.mark.parametrize("field", ["last_modified_at", "published_at", "cvss_score", "epss_score", "cve_id"])
@pytest.mark.parametrize("direction", ["asc", "desc"])
def test_sort_is_applied_before_pagination_and_preserves_filters(field, direction):
    session = Mock()
    session.scalar.return_value = 42
    session.scalars.return_value = []
    result = browse_cves(None, session, q="authentication", vendor="acme", kev=True,
                         page=2, page_size=20, sort_by=field, sort_order=direction)
    statement = session.scalars.call_args.args[0]
    compiled = statement.compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert f"ORDER BY cves.{field} {direction.upper()} NULLS LAST, cves.id DESC" in sql
    assert "%authentication%" in compiled.params.values()
    assert "%acme%" in compiled.params.values() and "is_kev IS true" in sql
    assert statement._limit_clause.value == 20 and statement._offset_clause.value == 20
    assert result["total"] == 42 and result["page"] == 2
