# Signup email verification

New signup is now two-step: POST `/auth/register` sends an email and returns only
a challenge ID (202). POST `/auth/register/verify` accepts `challenge_id` and a
six-digit `code`; only success creates the organization/user and returns a session.
Login continues to use a password. Existing accounts are unchanged.

The browser now preserves only the challenge ID, email and absolute expiry/resend
timestamps in sessionStorage so refreshing the same tab does not lose the OTP
screen. It does not persist the password or OTP. POST `/auth/register/resend`
accepts the current `challenge_id` and reuses the existing password hash; it
rotates the challenge without resetting the per-email send/guess budgets.
Expired screens allow resending; switching email clears local verification state.
OTP emails include a return link carrying only challenge metadata in the URL
fragment. Opening it restores verification, but never signs the user in; the
separate emailed code is still required. PUBLIC_APP_URL must point to the actual
application address. A localhost return link is usable only on the local machine.

Browser regression: with the local app running, run
`node node_modules/@playwright/test/cli.js test` from `frontend`. The test uses
headless Edge and mocked HTTP responses (no real mail/account); the separate
PostgreSQL test verifies actual signup/resend/verification and login using a
capture-only email adapter and rollback transaction. These tests do not prove
delivery into a real recipient's inbox.

Mail uses the same `SMTP_*` and `EMAIL_FROM_*` settings as alert delivery, through
the existing EmailSender/SMTP adapter. No new mail vendor or credentials are used.
The digest enable flag does not disable signup verification mail.

Codes expire after 10 minutes. Resending requires 60 seconds; at most five sends
and five wrong guesses are allowed per email per hour. Resending rotates the
challenge and invalidates older codes without resetting guesses. An additional
per-client-IP Redis limit fails closed if Redis is unavailable. Configure trusted
proxy client-IP forwarding for deployments; otherwise clients behind the same
proxy share its limit. Never trust arbitrary public forwarded IP headers.

Only password hashes and challenge-bound HMAC digests are stored, never plaintext
passwords/codes. Failed guesses are committed; successful verification consumes
the challenge in the same transaction as account creation. SMTP failure rolls
back the challenge and returns a retryable error. Abandoned pending signups are
purged after 24 hours by Celery beat. Keep worker/beat running for cleanup.

Apply migration `20260909_01` before starting the new API. The three-day monitoring
trial starts when verification creates the organization, not when email is sent.

## Local HTTP verification

With the local runner active, run `python scripts/check_local_auth.py` from the
repository root. It checks the rendered auth pages and the actual frontend API
routes, without credentials, account creation, or mail delivery. Mocked frontend
unit tests alone cannot detect a running Next development server serving stale
route state. The check expects JSON validation errors for empty signup/login
requests, not an HTML 404 page.

If existing route files return HTML 404 responses in development, stop the local
runner, move `frontend/.next/dev` to a uniquely named backup under `.next`, and
restart the runner to regenerate the development cache. Do not remove database
volumes or accounts. Re-run the HTTP check after startup. A successful check does
not prove SMTP delivery: complete signup using an unused email and its received
code to verify delivery end to end. Existing accounts should log in instead of
signing up again.
