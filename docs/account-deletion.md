# Account deletion

Plan & billing → Account settings → Delete my account sends a deletion-only OTP
to the authenticated user's registered email through the existing SMTP adapter.
POST `/auth/account/deletion-code` requests the challenge; POST
`/auth/account/delete` verifies `challenge_id` and `code` and deletes only that
user row. Every device's JWT becomes invalid because authentication reloads the
user on each request. The browser cookie is cleared after successful deletion.

Codes expire in ten minutes. Redis stores only HMAC digests bound to the user,
email, token version and challenge. Atomic Lua scripts enforce a 60-second resend
cooldown, five sends and five guesses per hour, and one-time consumption. Resends
do not reset attempt budgets. SMTP or Redis failures never authorize deletion.
If database commit fails after consuming a valid code, request a new code.

The application administrator and the last active organization owner cannot
self-delete. Arrange administrator reassignment or organization ownership
transfer with the operator first. Concurrent account deletions lock the same
organization row before checking ownership. Organization data, billing contacts,
transactions and subscriptions are retained; this is not workspace erasure,
subscription cancellation, or a promise to erase all personal data from backups.
No database migration is required. Restart API processes to load the new routes.

Tests must use disposable accounts and rollback transactions. Never delete a
real user's account merely to test this feature.
