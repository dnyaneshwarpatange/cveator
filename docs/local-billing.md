# Local billing and monitoring access

Monitoring is free for exactly 72 hours from organization creation. Restarting,
logging in, or adding a product does not extend the trial. Existing organizations
keep their original creation time. After expiry, alert APIs, new watchlist entries,
alert generation and digest/urgent delivery require an active paid period confirmed
by a signed provider webhook. Billing, login and removal of watchlist entries remain
available. No application-admin billing bypass is enabled.

Set `APPLICATION_ADMIN_USER_ID` to the administrator's immutable database user UUID.
Tenant owner/admin roles do not grant this privilege. Import status and internal
provenance in CVE details/history are restricted on the API, not just hidden in CSS.
Public remediation references remain available.

For Razorpay test checkout, configure a matching Test Mode API key pair in the
ignored `.env`, plus a webhook secret and `RAZORPAY_PLAN_IDS_JSON` mapping internal
plan IDs to plans from that same test account. `BILLING_PLANS_JSON` must be valid
JSON and its price/currency/interval must match the provider plan. Never commit keys.

After changing `.env`, recreate the API/worker/beat containers to load it:
`docker compose up -d --no-deps api worker beat`.

Razorpay cannot send webhooks directly to localhost. Configure a public HTTPS
forwarding endpoint for `/billing/webhooks/razorpay` on the API, with the matching
webhook secret. Subscribe to subscription activated, charged, cancelled, pending
and halted events. Do not expose the database, Redis, or admin endpoints.

Complete a Test Mode checkout (no real money), confirm the signed webhook was
processed, then refresh Plan & billing. Browser callback verification alone never
unlocks paid access. Replay the same event to verify it returns `duplicate`.

An HTTP 401 from the provider means the configured API key pair is not accepted;
application code or changing the plan JSON cannot repair gateway credentials.
