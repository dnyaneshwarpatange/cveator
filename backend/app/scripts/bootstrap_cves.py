"""Import official NVD yearly CVE feeds with verified downloads and page commits.

Run from backend: python -m app.scripts.bootstrap_cves --env-file ../.env
Default: every year, newest first. --years 2026 2025 limits the baseline explicitly.
An interrupted year safely replays from zero because the upstream may reorder;
already-identical records are skipped in batches. Completed years are retained.
"""

import argparse
from itertools import batched
from pathlib import Path

from app.scripts.import_catalog_keyword import _load_environment


def run_bootstrap(
    *, years: list[int] | None = None, batch_size: int = 500
) -> dict[str, int | bool]:
    """Bootstrap once from deployment or CLI, sharing the same cross-process lock.

    The caller supplies the environment. A completed baseline is a cheap no-op;
    setting its catch-up cursor and durable completion marker is atomic.
    """
    if not 1 <= batch_size <= 1000:
        raise ValueError("batch-size must be from 1 to 1000")

    from sqlalchemy import select, text

    from app.adapters.nvd_bulk import NVD_FIRST_FEED_YEAR, NvdYearlyFeed
    from app.core.time import utc_now
    from app.db.session import SessionLocal, engine
    from app.models.catalog_import import CatalogImport
    from app.services.cve_bulk import import_cve_batch

    current_year = utc_now().year
    years = sorted(set(years if years is not None else
                       range(NVD_FIRST_FEED_YEAR, current_year + 1)), reverse=True)
    if any(year < NVD_FIRST_FEED_YEAR or year > current_year for year in years):
        raise ValueError(f"feed years must be between {NVD_FIRST_FEED_YEAR} and {current_year}")
    if not years:
        raise ValueError("At least one year is required")
    required = {f"nvd_cves_{year}" for year in range(NVD_FIRST_FEED_YEAR, current_year + 1)}
    with engine.connect() as lock_connection:
        if not lock_connection.scalar(text("SELECT pg_try_advisory_lock(830425030)")):
            print("Another full CVE baseline import is already running", flush=True)
            return {"complete": False, "already_running": True, "years_imported": 0}
        feed = None
        years_imported = 0
        try:
            with SessionLocal.begin() as session:
                # Preserve obsolete failed checkpoints for audit, but do not
                # request nonexistent files or treat them as missing coverage.
                for year in range(1999, NVD_FIRST_FEED_YEAR):
                    obsolete = session.get(CatalogImport, f"nvd_cves_{year}")
                    if obsolete is not None:
                        obsolete.status, obsolete.error = "superseded", None
                completed_sources = set(
                    session.scalars(
                        select(CatalogImport.source).where(
                            CatalogImport.status == "complete",
                            CatalogImport.source.in_(required),
                        )
                    )
                )
                complete = _finalize_baseline(session, required)
            requested = {f"nvd_cves_{year}" for year in years}
            if requested <= completed_sources:
                print(
                    "Requested CVE baseline is already complete; existing cursor retained",
                    flush=True,
                )
                return {"complete": complete, "already_running": False, "years_imported": 0}
            feed = NvdYearlyFeed()
            for year in years:
                source = f"nvd_cves_{year}"
                with SessionLocal.begin() as session:
                    progress = session.get(CatalogImport, source)
                    if progress and progress.status == "complete":
                        print(
                            f"CVE {year}: already complete ({progress.total_results})", flush=True
                        )
                        continue
                    if progress is None:
                        progress = CatalogImport(source=source, started_at=utc_now())
                        session.add(progress)
                    # Indexes in a changed yearly snapshot are not stable. Replay safely.
                    progress.status, progress.error = "running", None
                    progress.next_start_index, progress.products_upserted = 0, 0
                    progress.total_results, progress.updated_at = 0, utc_now()
                print(f"CVE {year}: downloading and verifying official feed", flush=True)
                try:
                    with feed.records(year) as records:
                        count = 0
                        for batch in batched(records, batch_size):
                            with SessionLocal.begin() as session:
                                processed = import_cve_batch(session, batch)
                                count += len(batch)
                                progress = session.get(CatalogImport, source)
                                assert progress is not None
                                progress.next_start_index = count
                                progress.products_upserted += processed
                                progress.updated_at = utc_now()
                            print(f"CVE {year}: committed {count} records", flush=True)
                    if count == 0:
                        raise ValueError("Official yearly feed contained no CVE records")
                    with SessionLocal.begin() as session:
                        progress = session.get(CatalogImport, source)
                        assert progress is not None
                        progress.status, progress.total_results = "complete", count
                        progress.updated_at = utc_now()
                    print(f"CVE {year}: COMPLETE ({count} verified records)", flush=True)
                    years_imported += 1
                except Exception as exc:
                    with SessionLocal.begin() as session:
                        progress = session.get(CatalogImport, source)
                        if progress:
                            progress.status, progress.error = "failed", type(exc).__name__
                            progress.updated_at = utc_now()
                    raise
            # A partial/current-year import is never evidence of complete global coverage.
            with SessionLocal.begin() as session:
                complete = _finalize_baseline(session, required)
            return {
                "complete": complete,
                "already_running": False,
                "years_imported": years_imported,
            }
        finally:
            if feed is not None:
                feed.close()
            lock_connection.execute(text("SELECT pg_advisory_unlock(830425030)"))


def _finalize_baseline(session, required: set[str]) -> bool:
    """Only the first global completion establishes catch-up; reruns preserve progress."""
    from sqlalchemy import select

    from app.core.time import utc_now
    from app.models.catalog_import import CatalogImport
    from app.repositories.sqlalchemy_cve_repository import SqlAlchemyCveRepository

    completed = list(
        session.scalars(
            select(CatalogImport).where(
                CatalogImport.source.in_(required),
                CatalogImport.status == "complete",
            )
        )
    )
    if {item.source for item in completed} != required:
        return False
    marker = session.get(CatalogImport, "nvd_cves")
    if marker is not None and marker.status == "complete":
        return True
    earliest = min(item.started_at for item in completed)
    if marker is None:
        marker = CatalogImport(source="nvd_cves", started_at=earliest)
        session.add(marker)
    total = sum(item.total_results for item in completed)
    marker.status, marker.error = "complete", None
    marker.next_start_index, marker.total_results, marker.products_upserted = total, total, total
    marker.updated_at = utc_now()
    SqlAlchemyCveRepository(session).save_cursor("nvd", earliest)
    print(
        "Full NVD baseline complete; incremental catch-up starts " + earliest.isoformat(),
        flush=True,
    )
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=Path("../.env"))
    parser.add_argument("--years", nargs="+", type=int)
    parser.add_argument("--batch-size", type=int, default=500)
    args = parser.parse_args()
    _load_environment(args.env_file.resolve())
    run_bootstrap(years=args.years, batch_size=args.batch_size)


if __name__ == "__main__":
    main()
