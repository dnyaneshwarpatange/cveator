"""Load real NVD-backed watchlist data without sending a historical email flood."""

import argparse
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

REAL_PRODUCTS = (
    {
        "part": "o",
        "vendor": "fortinet",
        "product_name": "Fortinet FortiOS 7.4.0",
        "cpe_product": "fortios",
        "cpe_version": "7.4.0",
        "cpe_string": "cpe:2.3:o:fortinet:fortios:7.4.0:*:*:*:*:*:*:*",
    },
    {
        "part": "o",
        "vendor": "microsoft",
        "product_name": "Microsoft Windows Server 2022",
        "cpe_product": "windows_server_2022",
        "cpe_version": "-",
        "cpe_string": "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*",
    },
)


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
    parser.add_argument("--email", required=True, help="Existing local login email")
    parser.add_argument("--env-file", type=Path, default=Path("../.env"))
    parser.add_argument("--keep-demo", action="store_true")
    args = parser.parse_args()
    _load_environment(args.env_file.resolve())

    import httpx
    from sqlalchemy import delete, func, select, update

    from app.adapters.cisa_kev import CisaKevFeed
    from app.adapters.deterministic_summary import DeterministicSummaryGenerator
    from app.adapters.nvd import NVD_CVE_API_URL, normalize_nvd_vulnerability
    from app.core.config import get_settings
    from app.db.session import SessionLocal
    from app.domain.cve import NormalizedCve
    from app.domain.product import CatalogProduct
    from app.models.catalog import Alert, Product, User, WatchlistItem
    from app.models.cve import Cve
    from app.repositories.sqlalchemy_alert_repository import SqlAlchemyAlertRepository
    from app.repositories.sqlalchemy_catalog_repository import SqlAlchemyCatalogRepository
    from app.repositories.sqlalchemy_cve_repository import SqlAlchemyCveRepository
    from app.repositories.sqlalchemy_notification_repository import SqlAlchemyNotificationRepository
    from app.services.matching import CveProductMatcher
    from app.services.summaries import AlertSummaryService

    settings = get_settings()
    if settings.app_env.casefold() != "development":
        raise SystemExit("Real local bootstrap is allowed only in development")
    api_key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else ""
    if not api_key:
        raise SystemExit("NVD_API_KEY is required for this real-data bootstrap")

    with SessionLocal.begin() as session:
        user = session.scalar(select(User).where(func.lower(User.email) == args.email.casefold()))
        if user is None:
            raise SystemExit("Create or update the local user before bootstrapping its watchlist")
        org_id = user.org_id
        catalog = SqlAlchemyCatalogRepository(session)
        for item in REAL_PRODUCTS:
            catalog.upsert_product(CatalogProduct(**item))
        session.flush()
        real_product_ids = set(
            session.scalars(select(Product.id).where(
                Product.cpe_string.in_([item["cpe_string"] for item in REAL_PRODUCTS])
            ))
        )
        for product_id in real_product_ids:
            exists = session.scalar(select(WatchlistItem.id).where(
                WatchlistItem.org_id == org_id, WatchlistItem.product_id == product_id
            ))
            if exists is None:
                session.add(WatchlistItem(org_id=org_id, product_id=product_id))
        if not args.keep_demo:
            demo_cve_ids = select(Cve.id).where(Cve.cve_id.like("CVE-DEMO-%"))
            session.execute(
                delete(Alert).where(Alert.org_id == org_id, Alert.cve_id.in_(demo_cve_ids))
            )
            session.execute(delete(WatchlistItem).where(
                WatchlistItem.org_id == org_id,
                WatchlistItem.product_id.not_in(real_product_ids),
            ))

    imported_ids: set[str] = set()
    headers = {"apiKey": api_key}
    with httpx.Client(timeout=90, follow_redirects=True, headers=headers) as client:
        for item in REAL_PRODUCTS:
            start_index = 0
            while True:
                response = client.get(NVD_CVE_API_URL, params={
                    "cpeName": item["cpe_string"],
                    "resultsPerPage": settings.nvd_results_per_page,
                    "startIndex": start_index,
                })
                response.raise_for_status()
                payload = response.json()
                vulnerabilities = payload.get("vulnerabilities", [])
                with SessionLocal.begin() as session:
                    repository = SqlAlchemyCveRepository(session)
                    matcher = CveProductMatcher(repository)
                    for vulnerability in vulnerabilities:
                        record = normalize_nvd_vulnerability(vulnerability)
                        repository.upsert_cve(record)
                        matcher.match_record(record)
                        imported_ids.add(record.cve_id)
                start_index += len(vulnerabilities)
                print(f"NVD {item['product_name']}: {start_index}/{payload.get('totalResults', 0)}")
                if not vulnerabilities or start_index >= int(payload.get("totalResults", 0)):
                    break
                time.sleep(settings.nvd_rate_limit_interval_seconds)

        kev_feed = CisaKevFeed(url=settings.cisa_kev_url, client=client)
        kev_records = kev_feed.fetch_since(datetime.now(UTC)).records
        with SessionLocal.begin() as session:
            repository = SqlAlchemyCveRepository(session)
            for record in kev_records:
                if record.cve_id in imported_ids:
                    repository.upsert_cve(record)

        imported = sorted(imported_ids)
        for offset in range(0, len(imported), 100):
            batch = imported[offset:offset + 100]
            response = client.get(
                "https://api.first.org/data/v1/epss", params={"cve": ",".join(batch)}
            )
            response.raise_for_status()
            with SessionLocal.begin() as session:
                repository = SqlAlchemyCveRepository(session)
                for row in response.json().get("data", []):
                    repository.upsert_cve(NormalizedCve(
                        cve_id=row["cve"], source="epss", raw=row,
                        epss_score=float(row["epss"]),
                    ))

    started_at = datetime.now(UTC)
    with SessionLocal.begin() as session:
        alerts_created = SqlAlchemyAlertRepository(session).create_missing_alerts(org_id=org_id)
        generated = AlertSummaryService(
            SqlAlchemyNotificationRepository(session), DeterministicSummaryGenerator()
        ).generate_pending(limit=10_000)
        # Initial history is visible in the UI, but only future changes should trigger email.
        session.execute(update(Alert).where(
            Alert.org_id == org_id, Alert.sent_at.is_(None)
        ).values(sent_at=started_at))
        alert_count = session.scalar(select(func.count(Alert.id)).where(Alert.org_id == org_id))

    print(
        f"Real bootstrap complete: {len(imported_ids)} CVEs, {alerts_created} alerts created, "
        f"{generated} summaries generated, {alert_count} visible alerts."
    )


if __name__ == "__main__":
    main()
