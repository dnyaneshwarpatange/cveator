"""Import matching live products from the official NVD CPE dictionary."""

import argparse
import os
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def _load_environment(path: Path) -> None:
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) > 1 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ[key.strip()] = value
    database = urlsplit(os.environ["DATABASE_URL"])
    if database.hostname in {"postgres", "db"}:
        credentials = database.netloc.rsplit("@", 1)[0]
        os.environ["DATABASE_URL"] = urlunsplit(
            database._replace(netloc=f"{credentials}@127.0.0.1:5432")
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "keyword", help="NVD product or vendor keyword, for example 'Atlassian Jira'"
    )
    parser.add_argument("--env-file", type=Path, default=Path("../.env"))
    args = parser.parse_args()
    _load_environment(args.env_file.resolve())

    import httpx

    from app.adapters.nvd_cpe import NVD_CPE_API_URL, normalize_nvd_cpe_product
    from app.core.config import get_settings
    from app.db.session import SessionLocal
    from app.repositories.sqlalchemy_catalog_repository import SqlAlchemyCatalogRepository

    settings = get_settings()
    api_key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else ""
    headers = {"apiKey": api_key} if api_key else {}
    interval = settings.nvd_rate_limit_interval_seconds
    start_index = 0
    imported = 0
    total = None
    with httpx.Client(timeout=120) as client:
        while total is None or start_index < total:
            response = client.get(
                NVD_CPE_API_URL,
                params={
                    "keywordSearch": args.keyword,
                    "startIndex": start_index,
                    "resultsPerPage": settings.nvd_cpe_results_per_page,
                },
                headers=headers,
            )
            response.raise_for_status()
            payload = response.json()
            raw_products = payload.get("products", [])
            total = int(payload.get("totalResults", 0))
            with SessionLocal.begin() as session:
                repository = SqlAlchemyCatalogRepository(session)
                for raw_product in raw_products:
                    product = normalize_nvd_cpe_product(raw_product)
                    if product is not None:
                        repository.upsert_product(product)
                        imported += 1
            start_index += len(raw_products)
            print(f"Imported {imported}/{total} live products", flush=True)
            if not raw_products:
                break
            time.sleep(interval)
    print(f"Finished: {imported} active CPE entries for {args.keyword!r}")


if __name__ == "__main__":
    main()
