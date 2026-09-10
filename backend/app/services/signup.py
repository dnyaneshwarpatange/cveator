"""Email ownership is proved before any organization, user, trial or JWT exists."""

import hashlib
import hmac
import secrets
from datetime import timedelta
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
    def __init__(self, session: Session, sender: EmailSender, secret: str):
        self.session, self.sender, self.secret = session, sender, secret

    def _digest(self, challenge_id: UUID, code: str) -> str:
        return hmac.new(
            self.secret.encode(), f"signup:{challenge_id}:{code}".encode(), hashlib.sha256
        ).hexdigest()

    def start(self, *, organization_name: str, email: str, password: str) -> PendingSignup:
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
        pending.password_hash = hash_password(password)
        code = f"{secrets.randbelow(1_000_000):06d}"
        pending.code_hash = self._digest(pending.id, code)
        pending.expires_at = now + timedelta(minutes=10)
        pending.sent_at = now
        pending.sends += 1
        try:
            self.sender.send(
                OutboundEmail(
                    recipient=email,
                    subject="Verify your CVE Monitor email",
                    text_body=f"Your signup verification code is {code}. It expires in 10 minutes. "
                    "Do not share this code. If you did not request it, ignore this email.",
                    html_body=f"<p>Your signup verification code:</p><p><strong>{code}</strong></p>"
                    "<p>Expires in 10 minutes. Do not share this code. "
                    "If you did not request it, ignore this email.</p>",
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
