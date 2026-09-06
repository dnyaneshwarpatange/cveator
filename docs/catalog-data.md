# Catalog import and subscription matching

The application imports the entire official NVD CPE dictionary through the paginated
[NVD products API](https://nvd.nist.gov/developers/products). This is a global catalog,
not a collection of keyword samples. A bounded live lookup can populate a searched
product while the first import is still running.

Each official CPE entry retains its version and platform identity. The import also
derives one all-version family per CPE part, vendor, and product. The family CPE uses
ANY for version and platform fields. Catalog search returns these named families;
typing a patch number does not substitute a neighboring release. A subscription to
the Jira family therefore means all Jira versions, not a finding that the user's
installed Jira patch is affected.

From the backend directory, run:

```powershell
python -m app.scripts.bootstrap_catalog --env-file ../.env
```

The importer commits each page and its checkpoint together in `catalog_imports`.
Restarting the same command resumes the last committed `next_start_index`. Progress
counts raw upstream entries, including deprecated records; only active records are
imported. `--max-pages 1` is a bounded smoke run and `--families-only` derives families
from previously imported rows. Provider keys are read from environment configuration.
An advisory lock prevents two complete catalog imports from running concurrently.

When bootstrap completes, the incremental cursor starts at the beginning of the full
import, so changes made during bootstrap are collected on the next run. Incremental
requests use bounded modification windows. A partial window commits its products but
does not advance the window's cursor; replay after failure is safe because upserts
are idempotent. Temporary upstream failures retry without skipping the failed page.

The current applicability graph is limited to subscribed products. It does not build
millions of unused product-to-CVE relationships as the catalog grows. Adding a
subscription schedules its historical backfill. Global CVE browsing uses the CVE
projection independently of this graph.

NVD CPE applicability determines version-specific matches. Before NVD publishes
applicability, MITRE/CVE List CNA affected-product identities can match all-version
families and vendor subscriptions using exact normalized names or structured CPE
identities. Names alone never establish that an installed version is vulnerable.
Once NVD has published configurations, later CNA updates preserve that applicability;
an explicitly empty corrected NVD configuration removes current stale associations.
Historical organization alerts remain available.
