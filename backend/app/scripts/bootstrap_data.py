"""Initialize the complete public data baseline and refresh its risk signals."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path)
    args = parser.parse_args()
    if args.env_file:
        from app.scripts.import_catalog_keyword import _load_environment

        _load_environment(args.env_file.resolve())

    from app.db.session import SessionLocal
    from app.models.catalog_import import CatalogImport
    from app.scripts.bootstrap_catalog import run_bootstrap as import_catalog
    from app.scripts.bootstrap_cves import run_bootstrap as import_cves
    from app.services.cve_projection import backfill_cve_projections
    from app.tasks import rebuild_cve_product_matches, sync_cisa_kev, sync_epss

    with SessionLocal.begin() as session:
        count = backfill_cve_projections(session)
        print(f"Initialized {count} existing CVE projections", flush=True)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = [executor.submit(import_catalog), executor.submit(import_cves)]
        for result in results:
            result.result()
    with SessionLocal() as session:
        for source in ("nvd_cpe_dictionary", "nvd_cves"):
            checkpoint = session.get(CatalogImport, source)
            if checkpoint is None or checkpoint.status != "complete":
                raise RuntimeError(f"{source} baseline is not complete; retry initialization later")
    print(sync_cisa_kev(), flush=True)
    print(sync_epss(), flush=True)
    print(rebuild_cve_product_matches(), flush=True)
    print("Complete public data baseline is ready; scheduled updates maintain it.", flush=True)


if __name__ == "__main__":
    main()
