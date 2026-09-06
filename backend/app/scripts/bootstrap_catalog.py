"""Import the complete official CPE dictionary with durable per-page checkpoints.

Run from backend: python -m app.scripts.bootstrap_catalog --env-file ../.env
Re-running resumes the last committed page. --max-pages permits a bounded smoke run.
"""

import argparse
from pathlib import Path

from app.scripts.import_catalog_keyword import _load_environment


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=Path("../.env"))
    parser.add_argument("--max-pages", type=int)
    parser.add_argument("--families-only", action="store_true")
    args = parser.parse_args()
    _load_environment(args.env_file.resolve())
    run_bootstrap(max_pages=args.max_pages, families_only=args.families_only)


def run_bootstrap(*, max_pages: int | None = None, families_only: bool = False) -> None:
    """Run with the current environment; also usable by the background worker."""

    from sqlalchemy import text

    from app.adapters.nvd_cpe import NvdCpeDictionaryFeed
    from app.core.config import get_settings
    from app.core.time import utc_now
    from app.db.session import SessionLocal, engine
    from app.models.catalog_import import CatalogImport
    from app.repositories.sqlalchemy_catalog_repository import SqlAlchemyCatalogRepository

    settings = get_settings()
    source = NvdCpeDictionaryFeed.source_name
    # A session-level advisory lock survives page commits and prevents two bootstrap
    # processes from racing the same checkpoint. It is released on connection close.
    with engine.connect() as lock_connection:
        locked = lock_connection.scalar(text("SELECT pg_try_advisory_lock(830425029)"))
        if not locked:
            raise SystemExit("Another complete catalog import is already running")
        try:
            with SessionLocal.begin() as session:
                progress = session.get(CatalogImport, source)
                if progress and progress.status == "complete" and not families_only:
                    print("Full catalog is already imported; incremental sync maintains it.")
                    return
                # Every imported page already creates its families atomically.
                # Only legacy data before the first checkpoint needs a backfill.
                if families_only or progress is None:
                    families = SqlAlchemyCatalogRepository(session).backfill_families()
                    print(f"Existing catalog family groups processed: {families}", flush=True)
                if families_only:
                    return
                if progress is None:
                    progress = CatalogImport(source=source, started_at=utc_now())
                    session.add(progress)
                    session.flush()
                progress.status, progress.error = "running", None
                progress.updated_at = utc_now()
                start_index, started_at = progress.next_start_index, progress.started_at

            feed = NvdCpeDictionaryFeed(
                api_key=settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None,
                results_per_page=settings.nvd_cpe_results_per_page,
                request_interval_seconds=settings.nvd_rate_limit_interval_seconds,
            )
            try:
                for page_number, page in enumerate(feed.iter_pages(start_index=start_index)):
                    with SessionLocal.begin() as session:
                        repository = SqlAlchemyCatalogRepository(session)
                        count = repository.upsert_products(page.products)
                        progress = session.get(CatalogImport, source)
                        assert progress is not None
                        progress.next_start_index = page.next_start_index
                        progress.total_results = page.total_results
                        progress.products_upserted += count
                        progress.updated_at = utc_now()
                        if page.complete:
                            progress.status = "complete"
                            # Catch modifications during the import on the next incremental run.
                            repository.save_cursor(source, started_at)
                    print(
                        f"Catalog {page.next_start_index}/{page.total_results}; "
                        f"active entries this page={count}; complete={page.complete}", flush=True,
                    )
                    if max_pages and page_number + 1 >= max_pages:
                        print("Stopped at requested page limit; checkpoint retained", flush=True)
                        break
            except Exception as exc:
                with SessionLocal.begin() as session:
                    progress = session.get(CatalogImport, source)
                    if progress:
                        progress.status, progress.updated_at = "failed", utc_now()
                        # Store exception class only: provider requests may contain sensitive data.
                        progress.error = type(exc).__name__
                raise
            finally:
                feed.close()
        finally:
            lock_connection.execute(text("SELECT pg_advisory_unlock(830425029)"))


if __name__ == "__main__":
    main()
