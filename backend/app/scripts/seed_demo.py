"""Create an idempotent local-only workspace with representative dashboard data."""

from datetime import UTC, datetime

from sqlalchemy import select

from app.adapters.deterministic_summary import DeterministicSummaryGenerator
from app.core.config import get_settings
from app.core.security import hash_password
from app.db.session import SessionLocal
from app.domain.summary import AlertSummaryInput
from app.models.catalog import (
    Alert,
    CveProductMatch,
    Organization,
    Product,
    User,
    WatchlistItem,
)
from app.models.cve import Cve

DEMO_EMAIL = "demo@example.com"
LEGACY_DEMO_EMAIL = "demo@local.test"
DEMO_PASSWORD = "LocalDemoPassword!2026"


def main() -> None:
    if get_settings().app_env.lower() != "development":
        raise SystemExit("Demo data is only allowed in development environments")
    with SessionLocal.begin() as session:
        user = session.scalar(select(User).where(User.email == DEMO_EMAIL))
        if user is None:
            user = session.scalar(select(User).where(User.email == LEGACY_DEMO_EMAIL))
            if user is not None:
                user.email = DEMO_EMAIL
        if user is None:
            organization = Organization(name="CVEATOR IT Services")
            session.add(organization)
            session.flush()
            user = User(
                org_id=organization.id,
                email=DEMO_EMAIL,
                password_hash=hash_password(DEMO_PASSWORD),
                role="owner",
            )
            session.add(user)
            session.flush()

        products = [
            _upsert_product(
                session,
                vendor="Microsoft",
                name="Windows Server 2022",
                cpe_product="windows_server_2022",
                version="22H2",
            ),
            _upsert_product(
                session,
                vendor="Intuit",
                name="QuickBooks Desktop",
                cpe_product="quickbooks_desktop",
                version="2024",
            ),
            _upsert_product(
                session,
                vendor="Fortinet",
                name="FortiOS",
                cpe_product="fortios",
                version="7.4",
            ),
        ]
        for product in products:
            if session.scalar(
                select(WatchlistItem.id).where(
                    WatchlistItem.org_id == user.org_id,
                    WatchlistItem.product_id == product.id,
                )
            ) is None:
                session.add(WatchlistItem(org_id=user.org_id, product_id=product.id))

        demo_alerts = [
            ("CVE-DEMO-0001", 9.8, 0.72, True, products[2]),
            ("CVE-DEMO-0002", 8.1, 0.18, False, products[0]),
            ("CVE-DEMO-0003", 5.9, 0.02, False, products[1]),
        ]
        generator = DeterministicSummaryGenerator()
        for cve_id, cvss, epss, is_kev, product in demo_alerts:
            cve = session.scalar(select(Cve).where(Cve.cve_id == cve_id))
            if cve is None:
                cve = Cve(
                    cve_id=cve_id,
                    source_json={"demo": {"local_only": True}},
                    cvss_score=cvss,
                    epss_score=epss,
                    is_kev=is_kev,
                    published_at=datetime(2026, 9, 1, tzinfo=UTC),
                    last_modified_at=datetime(2026, 9, 4, tzinfo=UTC),
                )
                session.add(cve)
                session.flush()
            if session.scalar(
                select(CveProductMatch.id).where(
                    CveProductMatch.cve_id == cve.id,
                    CveProductMatch.product_id == product.id,
                )
            ) is None:
                session.add(CveProductMatch(cve_id=cve.id, product_id=product.id))
            if session.scalar(
                select(Alert.id).where(Alert.org_id == user.org_id, Alert.cve_id == cve.id)
            ) is None:
                summary_input = AlertSummaryInput(
                    cve_id=cve_id,
                    cvss_score=cvss,
                    epss_score=epss,
                    is_kev=is_kev,
                    published_at=cve.published_at,
                    products=(f"{product.vendor} {product.product_name} {product.cpe_version}",),
                )
                session.add(
                    Alert(
                        org_id=user.org_id,
                        cve_id=cve.id,
                        status="new",
                        plain_summary=generator.generate(summary_input),
                        summary_provider=generator.provider_name,
                        summary_generated_at=datetime.now(UTC),
                    )
                )

    print(f"Demo workspace ready: {DEMO_EMAIL} / {DEMO_PASSWORD}")


def _upsert_product(
    session, *, vendor: str, name: str, cpe_product: str, version: str
) -> Product:
    cpe_string = f"cpe:2.3:a:{vendor.casefold()}:{cpe_product}:{version}:*:*:*:*:*:*:*"
    product = session.scalar(select(Product).where(Product.cpe_string == cpe_string))
    if product is None:
        product = Product(
            part="a",
            vendor=vendor,
            product_name=name,
            cpe_product=cpe_product,
            cpe_version=version,
            cpe_string=cpe_string,
        )
        session.add(product)
        session.flush()
    return product


if __name__ == "__main__":
    main()
