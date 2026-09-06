"""Read-only check of the CVE data upstreams; no database is needed."""

import argparse
from datetime import timedelta
from pathlib import Path

import httpx

from app.adapters.cisa_kev import CisaKevFeed
from app.adapters.mitre import _changed_records_since, normalize_mitre_record
from app.adapters.nvd import NVD_CVE_API_URL, normalize_nvd_vulnerability
from app.adapters.nvd_cpe import NVD_CPE_API_URL, normalize_nvd_cpe_product
from app.core.config import Settings
from app.core.time import utc_now


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=Path("../.env"))
    args = parser.parse_args()
    settings = Settings(_env_file=args.env_file)
    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        nvd_response = client.get(NVD_CVE_API_URL, params={"cveId": "CVE-2024-3094"})
        nvd_response.raise_for_status()
        nvd_record = normalize_nvd_vulnerability(nvd_response.json()["vulnerabilities"][0])

        cpe_response = client.get(NVD_CPE_API_URL, params={"resultsPerPage": 1})
        cpe_response.raise_for_status()
        nvd_cpe = normalize_nvd_cpe_product(cpe_response.json()["products"][0])
        if nvd_cpe is None:
            raise RuntimeError("NVD CPE API returned a deprecated-only response")

        delta_response = client.get(settings.mitre_delta_log_url)
        delta_response.raise_for_status()
        changed = _changed_records_since(delta_response.json(), utc_now() - timedelta(days=30))
        if not changed:
            raise RuntimeError("MITRE delta log has no changes in its advertised retention window")
        mitre_change = next(iter(changed.values()))
        mitre_response = client.get(mitre_change["githubLink"])
        mitre_response.raise_for_status()
        mitre_record = normalize_mitre_record(mitre_response.json())

        cisa_feed = CisaKevFeed(url=settings.cisa_kev_url, client=client)
        cisa_result = cisa_feed.fetch_since(utc_now())
        if not cisa_result.records:
            raise RuntimeError("CISA KEV feed returned no records")

        epss_response = client.get(
            "https://api.first.org/data/v1/epss", params={"cve": nvd_record.cve_id}
        )
        epss_response.raise_for_status()
        epss_data = epss_response.json().get("data", [])
        if not epss_data:
            raise RuntimeError("FIRST EPSS API returned no score for the test CVE")
        epss_score = float(epss_data[0]["epss"])

    print(f"NVD: {nvd_record.cve_id} (CVSS {nvd_record.cvss_score})")
    print(f"NVD CPE: {nvd_cpe.vendor} {nvd_cpe.product_name}")
    print(f"MITRE: {mitre_record.cve_id}")
    print(f"CISA KEV: {len(cisa_result.records)} records")
    print(f"FIRST EPSS: {nvd_record.cve_id} ({epss_score:.3%})")


if __name__ == "__main__":
    main()
