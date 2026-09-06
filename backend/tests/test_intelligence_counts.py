from time import monotonic
from unittest.mock import Mock

from app.api import intelligence


def test_expired_counts_return_immediately_and_start_only_one_refresh(monkeypatch):
    counts = {"cves": 42, "products": 100, "product_families": 10}
    monkeypatch.setattr(intelligence, "_counts_cache", (0, counts))
    monkeypatch.setattr(intelligence, "_counts_refreshing", False)
    thread = Mock()
    monkeypatch.setattr(intelligence, "Thread", thread)
    session = Mock()
    assert intelligence._database_counts(session) == counts
    assert intelligence._database_counts(session) == counts
    thread.assert_called_once()
    thread.return_value.start.assert_called_once()
    session.scalar.assert_not_called()


def test_restart_uses_persisted_public_counts_without_blocking_on_database(monkeypatch):
    counts = {"cves": 42, "products": 100, "product_families": 10}
    monkeypatch.setattr(intelligence, "_counts_cache", (0, {}))
    monkeypatch.setattr(intelligence, "_counts_refreshing", False)
    monkeypatch.setattr(intelligence, "read_counts", lambda: counts)
    monkeypatch.setattr(intelligence, "Thread", Mock())
    session = Mock()
    assert intelligence._database_counts(session) == counts
    session.scalar.assert_not_called()


def test_fresh_counts_do_not_start_background_work(monkeypatch):
    counts = {"cves": 42, "products": 100, "product_families": 10}
    monkeypatch.setattr(intelligence, "_counts_cache", (monotonic() + 60, counts))
    monkeypatch.setattr(intelligence, "_counts_refreshing", False)
    thread = Mock()
    monkeypatch.setattr(intelligence, "Thread", thread)
    assert intelligence._database_counts(Mock()) == counts
    thread.assert_not_called()
