"""Email ownership is proved before any organization, user, trial or JWT exists."""

import hashlib
import hmac
import secrets
import json
from datetime import timedelta
from html import escape
from urllib.parse import quote
from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.security import hash_password, normalize_email
from app.core.time import utc_now
from app.domain.auth import EmailAlreadyRegistered
from app.domain.notifications import OutboundEmail
from app.models.signup import PendingSignup
from app.ports.email_sender import EmailSender
from app.repositories.sqlalchemy_auth_repository import SqlAlchemyAuthRepository


class SignupThrottled(Exception):
    pass


class SignupMailUnavailable(Exception):
    pass


class SignupService:
    def __init__(self, session: Session, sender: EmailSender, secret: str, public_app_url: str = ""):
        self.session, self.sender, self.secret = session, sender, secret
        self.public_app_url = public_app_url.rstrip("/")

    def _digest(self, challenge_id: UUID, code: str) -> str:
        return hmac.new(
            self.secret.encode(), f"signup:{challenge_id}:{code}".encode(), hashlib.sha256
        ).hexdigest()

    def resend(self, challenge_id: UUID) -> PendingSignup:
        pending = self.session.get(PendingSignup, challenge_id)
        if not pending:
            raise ValueError("Verification request expired. Start signup again.")
        return self.start(organization_name=pending.organization_name, email=pending.email,
                          password=None, expected_challenge=challenge_id)

    def start(self, *, organization_name: str, email: str, password: str | None,
              expected_challenge: UUID | None = None) -> PendingSignup:
        email = normalize_email(email)
        # Serialize new requests too, even when there is no existing row to lock.
        lock_id = int.from_bytes(hashlib.sha256(email.encode()).digest()[:8], signed=True)
        self.session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_id})
        repository = SqlAlchemyAuthRepository(self.session)
        if repository.get_by_email(email):
            raise EmailAlreadyRegistered
        pending = self.session.scalar(
            select(PendingSignup).where(PendingSignup.email == email).with_for_update()
        )
        if password is None and (not pending or pending.id != expected_challenge):
            raise ValueError("Verification request changed. Start signup again.")
        stored_hash = pending.password_hash if password is None else None
        now = utc_now()
        if pending and now < pending.window_started_at + timedelta(hours=1):
            if (
                pending.sends >= 5
                or pending.attempts >= 5
                or now < pending.sent_at + timedelta(seconds=60)
            ):
                raise SignupThrottled
        else:
            if pending:
                self.session.delete(pending)
                self.session.flush()
            pending = PendingSignup(email=email, window_started_at=now, sends=0, attempts=0)
            self.session.add(pending)
        pending.id = uuid4()
        pending.organization_name = organization_name.strip()
        pending.password_hash = hash_password(password) if password is not None else stored_hash
        code = f"{secrets.randbelow(1_000_000):06d}"
        pending.code_hash = self._digest(pending.id, code)
        pending.expires_at = now + timedelta(minutes=10)
        pending.sent_at = now
        pending.sends += 1
        # Fragment metadata does not contain the OTP/password and is not sent in HTTP logs.
        resume_url = self.public_app_url + "/register#verification=" + quote(json.dumps({
            "id": str(pending.id), "email": email,
            "expiresAt": int(pending.expires_at.timestamp() * 1000),
            "resendAt": int((now + timedelta(seconds=60)).timestamp() * 1000),
        })) if self.public_app_url else ""
        try:
            self.sender.send(
                OutboundEmail(
                    recipient=email,
                    subject="Verify your cveator email",
                    text_body=f"Your signup verification code is {code}. It expires in 10 minutes. "
                    "Do not share this code. If you did not request it, ignore this email."
                    + (f"\nReturn to verification: {resume_url}" if resume_url else ""),
                    html_body=f"<p>Your signup verification code:</p><p><strong>{code}</strong></p>"
                    "<p>Expires in 10 minutes. Do not share this code. "
                    "If you did not request it, ignore this email.</p>"
                    + (f'<p><a href="{escape(resume_url, quote=True)}">Return to verification</a></p>' if resume_url else ""),
                )
            )
        except Exception as error:
            raise SignupMailUnavailable from error
        return pending

    def verify(self, challenge_id: UUID, code: str):
        pending = self.session.scalar(
            select(PendingSignup).where(PendingSignup.id == challenge_id).with_for_update()
        )
        if not pending or utc_now() >= pending.expires_at or pending.attempts >= 5:
            return None
        pending.attempts += 1
        if not hmac.compare_digest(pending.code_hash, self._digest(pending.id, code)):
            return None
        repository = SqlAlchemyAuthRepository(self.session)
        if repository.get_by_email(pending.email):
            self.session.delete(pending)
            return None
        user = repository.create_organization_owner(
            organization_name=pending.organization_name,
            email=pending.email,
            password_hash=pending.password_hash,
        )
        self.session.delete(pending)
        return user
