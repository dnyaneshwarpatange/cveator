# cveator

A self-hosted vulnerability workspace for small businesses. The responsive dashboard includes a prioritized alert inbox, software search and watchlist, plain-language next steps, and role-aware billing. Email, payment credentials, production DNS, and recovery checks must be configured before customer launch.

**One-command local setup:** with Docker Compose and Python 3.12+ installed, run `python scripts/deploy.py` (or double-click `start-local.cmd` on Windows). It preserves existing secrets, builds images, runs migrations, waits for readiness, and starts the real public-data baseline importer. The default URL is `http://localhost:3000/login`. Add `--demo` only when you explicitly want synthetic demonstration records.

Phase 1 implements an independently runnable CVE-ingestion foundation:

- NVD CVE API 2.0, paginated and incremental by `lastModStartDate`/`lastModEndDate`.
- The official CVE List V5 delta log published by the CVE Program/MITRE, including its record URLs.
- CISA's Known Exploited Vulnerabilities (KEV) catalog.
- FIRST's public daily EPSS score file, which is required because the three CVE feeds do not publish EPSS.
- PostgreSQL storage with raw provider payloads in `cves.source_json` and queryable CVSS/KEV fields.
- Celery tasks for scheduled synchronization.

Phase 2 adds the NVD CPE product catalog, PostgreSQL `pg_trgm` fuzzy search, CPE-aware CVE-to-product matching, and the storage tables required for organization watchlists.

Phase 3 adds self-hosted authentication and tenant isolation without an auth SaaS:

- Argon2 password hashes and short-lived signed JWT access tokens, with issuer, audience, expiry, not-before, and token-version claims.
- `owner`, `admin`, `member`, and `viewer` organization roles. The current database role is checked on every authenticated request, so a deactivated account, changed role, changed organization, or incremented token version invalidates a formerly valid token.
- Organization-scoped user administration and authenticated watchlist routes. The tenant ID is derived only from the verified principal; the repositories bind it into each watchlist read, insert, and delete, rather than accepting an organization ID from the client.
- A case-insensitive unique email constraint. An owner creates an organization at registration; owners or admins can provision members. Email invitation and reset delivery deliberately wait for the self-hosted SMTP phase.

Phase 4 adds the dashboard and alert feed:

- A Next.js App Router and Tailwind dashboard with sign-in, registration, product search, watchlist management, severity/status filtering, and alert acknowledgement.
- The Next.js server stores the API access token only in an HttpOnly, same-site cookie. Browser code talks only to same-origin Next.js route handlers; the server attaches the bearer token while forwarding to FastAPI. `API_INTERNAL_BASE_URL` is deliberately server-only and must never be changed to a `NEXT_PUBLIC_*` variable.
- An idempotent alert projection from global `cve_product_matches` into `alerts`, keyed by `(org_id, cve_id)`. It runs after each source sync and when a product is added to a watchlist. Alert reads and status changes are scoped to the authenticated organization in the repository layer.
- A `SummaryGenerator` port and provider-neutral summary storage fields. No LLM adapter or API key has been added: wiring Claude would introduce a second external API dependency and requires explicit approval before implementation.

Phase 5 adds recurring billing behind a provider-owned boundary:

- Generic `PaymentProvider` and billing-repository ports. The database uses only portable names: `payment_provider`, `provider_customer_id`, `provider_subscription_id`, and `provider_payment_id`; no gateway-owned column names exist in the core schema.
- The initial `backend/app/providers/razorpay/razorpay_payment_provider.py` adapter lives entirely in `providers/razorpay/` and uses documented REST endpoints rather than a gateway SDK. The core billing API, service, repositories, models, and dashboard do not import it or name it.
- Subscription checkout creates a provider customer and subscription, verifies the browser callback server-side, and remains pending until a server-to-server webhook confirms the state. The checkout HMAC is calculated over `payment_id|subscription_id`; this ordering is specific to subscription checkout. [Razorpay subscription integration guide](https://razorpay.com/docs/payments/subscriptions/integration-guide/)
- Webhooks read the raw request body before any parsing, verify the HMAC, and insert the provider event ID under a unique constraint before applying any billing change. Duplicate delivery returns success without a repeated state transition. [Razorpay webhook validation guidance](https://razorpay.com/docs/webhooks/validate-test/)
- The dashboard loads a provider-specific checkout script only after an administrator chooses a plan. The payment token remains in the frontend's HttpOnly session cookie and is never returned to browser JavaScript.

Phase 6 adds transactional alert delivery without a mail or AI SaaS:

- A vendor-neutral `EmailSender` port with a standard SMTP adapter. The adapter supports an internal plaintext connection to the bundled mail container, STARTTLS, or implicit TLS, plus optional SMTP authentication.
- A deterministic `SummaryGenerator` implementation produces stored, plain-language action summaries. KEV entries explicitly call out known active exploitation; CVSS 9+ entries receive critical guidance; elevated EPSS entries are prioritized without presenting probability as certainty. No Anthropic or other model API has been wired in.
- Celery checks every minute for unsent KEV or CVSS 9+ alerts and sends an urgent organization batch. A daily UTC schedule sends all remaining unsent alerts as one digest per organization. Every active user receives an individual message, so member addresses are never exposed to one another.
- When NVD, MITRE, or CISA materially changes an existing record, its matching alerts are reopened, their stale summaries are cleared, and the updated facts can be delivered again. Daily EPSS fluctuations update the score without repeatedly reopening an alert.
- Pending alert rows use `FOR UPDATE SKIP LOCKED` while a worker submits mail, preventing concurrent real-time and digest workers from claiming the same alert. `sent_at` is written only after every active recipient is accepted by SMTP; failures remain pending for retry. SMTP cannot make the final database commit atomic with delivery, so a worker crash in that narrow interval can still cause an at-least-once duplicate.
- An optional locally built Postfix/OpenDKIM container is available through the Compose `mail` profile. It is outbound-only and has no published host port, so it cannot become a public relay. Postfix trusts only loopback and private container networks and signs mail with a mounted DKIM private key.

Phases 7 and 8 add the production operating surface:

- The API exposes liveness (`GET /healthz`), dependency-aware readiness (`GET /readyz`), and Prometheus metrics (`GET /metrics`). Requests receive correlation IDs, structured JSON logs, latency metrics, and defensive response headers.
- PostgreSQL and Redis checks gate API readiness. Authentication is rate-limited through Redis, webhook bodies are size-limited before processing, and database connections use bounded pools with recycling.
- Containers run as non-root users where the upstream image supports it. Alembic migrations finish before the API, workers, or scheduler start. All application and database ports bind to loopback by default; the optional Caddy edge profile is the public entry point.
- The dashboard rejects cross-site state-changing API requests and stores production access tokens in a secure `__Host-` HttpOnly cookie. It ships as a standalone Next.js image with security headers and no framework disclosure header.
- The provider-neutral `StorageProvider` port and S3-protocol adapter are implemented. MinIO's official community repository was archived in April 2026 and its README now describes source-only maintenance, so this repository does not pin an abandoned binary into the production stack. Connect `STORAGE_*` settings to a maintained self-hosted S3-compatible service selected by the operator. [MinIO project notice](https://github.com/minio/minio/blob/master/README.md?plain=1)
- Self-hosted Prometheus and Uptime Kuma profiles replace managed monitoring services, preserving the requirement that Razorpay is the only approved third-party SaaS dependency. Backups use a validated, compressed PostgreSQL dump with retention, but the resulting files must also be encrypted and copied off the VPS.

An external AI summarizer remains deliberately unconfigured pending explicit approval. The deterministic local summarizer produces and stores actionable plain-language summaries independently of email delivery.

`GET /catalog/products?q=quickbooks` provides a public, read-only fuzzy product lookup. It returns a human-facing vendor, product name, and version—not CPE strings. Watchlist operations require a bearer token:

- `POST /auth/register`, `POST /auth/login`, and `GET /auth/me`
- `GET|POST|DELETE /watchlist[/{product_id}]`
- `GET|POST /organization/users` (owner/admin only)
- `GET /alerts`, `PATCH /alerts/{alert_id}`, and `GET /alerts/dashboard/overview`
- `GET /billing/plans`, `GET /billing/subscription`, `POST /billing/checkout`, `POST /billing/checkout/verify`, and `POST /billing/subscription/cancel`

For production, set `APP_ENV=production` and a unique random `JWT_SECRET` of at least 32 characters. Startup rejects the example or development secret in non-development environments.

## Run locally

1. Start Docker and run `python scripts/deploy.py --demo`. Existing `.env` files are preserved; review their credentials before use.
2. Open `http://localhost:3000/login` and sign in as `demo@example.com` using `LocalDemoPassword!2026` (development-only credentials).
3. To restart already built images, run `python scripts/deploy.py --demo --no-build`.

On memory-constrained Windows machines, use `python scripts/run_local.py` instead. Install `backend` dependencies with `python -m pip install -e "./backend[dev]"` and frontend dependencies with `npm --prefix frontend ci` first. This starts PostgreSQL/Redis in Docker and runs the API and dashboard on the host at `http://localhost:3002/login`. It does **not** start background ingestion or email jobs. To preview an optimized bundle, run `npm --prefix frontend run build` while the preview is stopped, then `python scripts/run_local.py --built`.

For a production-like local run, use `python scripts/run_local.py --built --full --no-demo`. `--full` starts the Celery worker, scheduler, and resumable full-data importer; `--no-demo` prevents synthetic records from being recreated. Add `--enable-email` only after validating SMTP and suppressing or reviewing an initial historical backlog. Email recipients are the login addresses of all active users in each organization. `start-preview.cmd` uses the built bundle and enables your configured SMTP delivery.

The **Vulnerability database** view browses all imported CVEs, independently of the watchlist. Its status panel shows actual catalog/yearly import checkpoints. Global counts refresh in the background at one-minute intervals; the last successful values remain available during slow refreshes, with `counts_updated_at` in the API response. First-time loading is substantial and may take hours on a constrained laptop. Keep Docker and the launcher running. Restarting resumes committed catalog pages and safely replays the interrupted CVE year. Only a completed baseline is labelled complete.

Software search groups the official CPE dictionary into **all-version product families**. A version-bearing search such as `Jira 9.12.36` searches the Jira family; it does not silently substitute a nearby installed patch. Vendor subscriptions monitor all the vendor's products. Adding a subscription queues an independent historical NVD lookup so the alert feed can populate before the global baseline finishes. Confirm your installed version against the vendor advisory before treating a family alert as proof of exposure.

Source payloads are retained separately, normalized into a shared CVE view, and meaningful changes are stored as history. CNA/MITRE descriptions and per-version scores take precedence with NVD fallback; KEV and EPSS enrich risk separately. This implementation is original and uses the public upstream feeds, not copied OpenCVE application code or its prebuilt knowledge base. It does not claim full OpenCVE feature parity.

Compose automatically waits for PostgreSQL, applies every Alembic migration, waits for API readiness, and then starts the dashboard. Inside Compose the frontend uses the private `api` service hostname; it does not expose a bearer token or internal API URL to browser JavaScript. PostgreSQL, Redis, API, and dashboard ports bind to loopback by default.

The demo records exercise the dashboard without waiting for a large external data backfill. Full Compose and `run_local.py --full` automatically bootstrap live public data, then maintain it with scheduled incremental jobs. A free NVD API key is strongly recommended. See `docs/catalog-data.md` for manual resume commands and progress interpretation.

## Production deployment and operations

This is a portable single-VPS deployment, not a high-availability topology. Before accepting customers, put database and object data on independently backed-up durable storage, test restoration on another machine, and decide whether the recovery objectives require a second host or managed infrastructure.

1. Copy `.env.production.example` to a secret file outside version control and fill every required value. Use generated credentials, set `APP_ENV=production`, disable API docs, use explicit allowed hosts, enable secure session cookies, and configure the HTTPS public URL.
2. Complete Razorpay KYC, create live recurring plans, configure the live webhook URL, and map internal plan IDs to provider plan IDs. Razorpay documents separate test/live modes; production keys and entities do not cross between them. [Razorpay test and live modes](https://razorpay.com/docs/payments/dashboard/test-live-modes/?preferred-country=IN)
3. Finish the self-hosted mail DNS/PTR and reputation work below. Enable delivery only after a signed test message passes SPF, DKIM, and DMARC checks.
4. Select a maintained self-hosted S3-compatible implementation, configure `STORAGE_*`, and exercise put/get/delete and backup recovery. The application adapter is endpoint-neutral; deployment guidance is in `infra/storage/README.md`.
5. Point the domain's A/AAAA records at the VPS. On first use, prepare the secrets, mail key, and provider configuration above; these account and DNS prerequisites cannot be automated from this repository.
6. Deploy with `python3 scripts/deploy.py --production --env-file .env.production` (or `./deploy.sh --production`). The launcher validates the target and DKIM key, builds images, runs the fail-closed application configuration audit, backs up an already-running database before migration, starts the public stack, waits for health checks, and checks the HTTPS login page. Caddy obtains and renews HTTPS certificates for `APP_ADDRESS`. A failed gate exits nonzero; this is not an automatic migration rollback system. Use `--no-build` only for images already built and verified.
7. Access Prometheus and Uptime Kuma only through an SSH tunnel to loopback ports 9090 and 3001. Configure an uptime check for `http://api:8000/readyz`; alert on sustained failures rather than liveness alone.
8. Run `ENV_FILE=.env.production docker compose --env-file .env.production --profile maintenance run --rm backup` on a scheduled Linux host job. On PowerShell, set `$env:ENV_FILE` to the production file first. Encrypt and copy dumps off-host, monitor job failures, and regularly restore the newest dump into an isolated database.
9. Complete one real paid signup, verify the subscription only activates from its webhook, replay that webhook to prove idempotency, send both digest classes, and confirm a restore before opening registration. Razorpay provides test subscriptions specifically for exercising the workflow before live activation. [Razorpay subscription testing](https://razorpay.com/docs/payments/subscriptions/test/)

Production image versions are pinned in Compose, and the Python container installs the exact runtime set in `backend/requirements.lock`. Review upstream security releases before upgrades, regenerate the lock deliberately, rebuild in a staging environment, run the verification suite, and only then roll the changed images into production.

## Billing configuration and test mode

1. In the Razorpay Dashboard, enable Subscriptions and create the recurring Plans you intend to sell. A subscription must reference a plan and a bounded `total_count` or end date. [Create Subscription API](https://razorpay.com/docs/api/payments/subscriptions/create-subscription/)
2. Copy `.env.example` to `.env`. Set `PAYMENT_PROVIDER`, give each customer-facing internal plan in `BILLING_PLANS_JSON` a corresponding provider plan ID in `RAZORPAY_PLAN_IDS_JSON`, and set test-mode key ID, key secret, and webhook secret. Never put those values in `frontend/.env.local` or any `NEXT_PUBLIC_*` variable.
3. Configure the webhook URL as `https://<your-api-host>/billing/webhooks/razorpay`. Subscribe to `subscription.activated`, `subscription.charged`, `subscription.cancelled`, `subscription.pending`, and `subscription.halted`. Razorpay documents the first three as activation/charge/cancellation state transitions and retries failures through pending/halted states. [Subscription webhook events](https://razorpay.com/docs/payments/subscriptions/subscribe-to-webhooks/)
4. Exercise the full flow with test-mode credentials and Razorpay’s current test payment methods. Use webhook delivery/replay tools to confirm that sending the same `X-Razorpay-Event-Id` twice produces only one database state transition.
5. Complete KYC, configure live credentials and live Plans, then perform a real paid end-to-end signup before accepting customers. The code switch is configuration-only, but KYC approval and your configured Plans are operational prerequisites.

The checkout callback only proves that the browser returned an authentic signature; it is not the payment-state authority. A lost browser callback does not prevent the webhook path from activating the subscription.

## Self-hosted email setup

Do not enable delivery until the identity and reputation controls below are in place. A fresh VPS IP will not have the reputation of a managed mail service, and some VPS providers block outbound TCP port 25 by default.

1. Choose a sending domain and hostname, such as `example.com` and `mail.example.com`. Point the hostname's A/AAAA record to the VPS. Ask the VPS provider to set the matching PTR record back to that exact hostname and confirm outbound port 25 is permitted.
2. Build the local image, then generate a 2048-bit key. `DKIM_SELECTOR` must match the generated filename and DNS selector:

   ```powershell
   docker compose --profile mail build smtp
   docker run --rm --entrypoint opendkim-genkey -v "${PWD}/infra/postfix/secrets:/keys" cve-monitor-postfix:local -b 2048 -D /keys -d example.com -s alerts
   ```

3. Publish the generated `alerts.txt` value as a TXT record at `alerts._domainkey.example.com`. OpenDKIM uses the matching private file only inside the mail container. Its documented single-domain configuration uses `Domain`, `Selector`, and `KeyFile`. [OpenDKIM configuration reference](https://www.opendkim.org/opendkim.conf.5.html)
4. Publish an SPF TXT record for the actual public sending IP, for example `v=spf1 ip4:203.0.113.10 -all`. Publish DMARC initially in reporting mode, for example `v=DMARC1; p=none; adkim=s; aspf=s`. Add a `rua=mailto:` target only after that address is served by infrastructure you control, then move to `quarantine` or `reject` after reviewing reports. DMARC evaluates alignment between the visible From domain and authenticated SPF or DKIM identifiers. [Current DMARC specification](https://www.rfc-editor.org/info/rfc9989/)
5. Set `MAIL_DOMAIN`, `MAIL_HOSTNAME`, `DKIM_SELECTOR`, `EMAIL_FROM_ADDRESS`, and `PUBLIC_APP_URL` in `.env`. For the bundled container keep `SMTP_HOST=smtp`, `SMTP_PORT=25`, and `SMTP_SECURITY=none`; this hop stays on the private Compose network. Then set `EMAIL_DELIVERY_ENABLED=true`.
6. Start the stack with `docker compose --profile mail up --build`. The Postfix outbound client uses opportunistic TLS for remote delivery, the documented `smtp_tls_security_level = may` behavior. [Postfix TLS reference](https://www.postfix.org/TLS_README.html)
7. Trigger bounded checks manually with `celery -A app.worker.celery_app call app.tasks.send_realtime_alerts` and `celery -A app.worker.celery_app call app.tasks.send_daily_digests`. Inspect `docker compose logs smtp worker` for rejection or signing errors, and verify a received message's SPF, DKIM, and DMARC results before relying on the schedule.

Postfix's relay policy permits only configured trusted networks before rejecting unauthorized destinations, matching its documented `permit_mynetworks`/`reject_unauth_destination` pattern. [Postfix relay controls](https://www.postfix.org/SMTPD_ACCESS_README.html) Keep monitoring Postfix logs, delayed bounces, DMARC aggregate reports, complaint feedback loops offered by major mailbox providers, and public blocklists. This operational work replaces the deliverability management a hosted sender would otherwise perform.

For a first NVD backfill, `NVD_INITIAL_SYNC_START` controls the beginning of the historical range. It is intentionally explicit: a full NVD history is large and is rate-limited by NVD. An NVD API key raises the permitted request rate; set `NVD_API_KEY` before a full bootstrap.

The MITRE/CVE adapter uses `cves/deltaLog.json`, whose retention is intentionally short. On an empty database it consumes the available log window; NVD provides the durable historical bootstrap. Deployments must schedule this job often enough to stay inside the delta-log retention period.

The CPE dictionary bootstrap is also large. It runs with NVD's documented API rate limit and triggers a bounded match backfill when the catalog sync completes. A free NVD API key is strongly recommended before either historical bootstrap.

## Verification

Deployment guard tests (no external services required): `python -m unittest discover -s scripts -p "test_*.py"`.

Run the isolated test suite from `backend`:

```powershell
pytest
```

Run the dashboard checks from `frontend`:

```powershell
npm run test
npm run typecheck
npm run lint
npm run build
```

An upstream smoke test is available after dependencies are installed:

```powershell
python -m app.scripts.smoke_upstreams --env-file ../.env
```

It performs small, read-only requests against NVD's CVE and CPE APIs, the official CVE List V5, and CISA; it does not write to the database.

Validate deployment configuration and container wiring with:

```powershell
docker compose config --quiet
docker compose --profile edge --profile mail --profile monitoring --profile maintenance config --quiet
python -m app.scripts.production_preflight
```

The final command is expected to fail under development settings; it succeeds only with a fully populated production configuration.

## Data sources

The service uses the [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities), the [official CVE List V5](https://github.com/CVEProject/cvelistV5), CISA's [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and FIRST's [daily EPSS data](https://www.first.org/epss/data.html). The CVE List V5 repository documents that its delta log is rolling and that records may contain CNA, CVE Program, and ADP containers; raw source records are therefore retained rather than destructively flattened.
