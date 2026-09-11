"""Single-use account-bound deletion challenges; Redis failures fail closed."""
import hashlib
import hmac
import secrets
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select

from app.domain.notifications import OutboundEmail
from app.models.catalog import Organization, User
from app.services.access import is_application_admin


class AccountDeletion:
    def __init__(self, session, redis, sender, secret):
        self.session, self.redis, self.sender, self.secret = session, redis, sender, secret

    def eligible_user(self, principal):
        # Serialize deletions in one organization so two owners cannot both leave.
        self.session.scalar(select(Organization).where(Organization.id == principal.org_id).with_for_update())
        user = self.session.scalar(select(User).where(
            User.id == principal.user_id, User.org_id == principal.org_id,
            User.is_active.is_(True), User.token_version == principal.token_version,
        ).with_for_update())
        if not user:
            raise HTTPException(401, "Account is no longer available.")
        if is_application_admin(user.id):
            raise HTTPException(409, "The application administrator cannot self-delete. Reassign application administration first.")
        if user.role == "owner" and not self.session.scalar(select(User.id).where(
            User.org_id == user.org_id, User.id != user.id, User.role == "owner", User.is_active.is_(True),
        ).limit(1)):
            raise HTTPException(409, "Another active organization owner is required. Contact the application administrator to transfer ownership or close the workspace.")
        return user

    def digest(self, user, challenge, code):
        value = f"delete:{user.id}:{user.token_version}:{user.email}:{challenge}:{code}"
        return hmac.new(self.secret.encode(), value.encode(), hashlib.sha256).hexdigest()

    def start(self, principal):
        user = self.eligible_user(principal)
        key = f"account-delete:{user.id}"
        # Send and guess budgets survive resends; all reservations are atomic.
        allowed = self.redis.eval("""
            if redis.call('EXISTS', KEYS[1] .. ':cooldown') == 1 then return 0 end
            local n = tonumber(redis.call('GET', KEYS[1] .. ':sends') or '0')
            local a = tonumber(redis.call('GET', KEYS[1] .. ':attempts') or '0')
            if n >= 5 or a >= 5 then return 0 end
            if redis.call('INCR', KEYS[1] .. ':sends') == 1 then redis.call('EXPIRE', KEYS[1] .. ':sends', 3600) end
            redis.call('SET', KEYS[1] .. ':cooldown', '1', 'EX', 60)
            return 1
        """, 1, key)
        if not allowed:
            raise HTTPException(429, "Wait 60 seconds before resending. Maximum five codes or guesses per hour.")
        challenge, code = str(uuid4()), f"{secrets.randbelow(1_000_000):06d}"
        self.redis.set(key, self.digest(user, challenge, code), ex=600)
        try:
            self.sender.send(OutboundEmail(
                recipient=user.email, subject="Confirm deletion of your cveator account",
                text_body=f"Your account deletion code is {code}. It expires in 10 minutes. Using this code to confirm deletion permanently removes your login account, not your organization's records or subscription. If this wasn't you, do not share or use the code.",
                html_body=f"<p>Your account deletion code: <strong>{code}</strong></p><p>Expires in 10 minutes. Confirming permanently deletes your login account, not your organization's records or subscription. If this wasn't you, do not share or use this code.</p>",
            ))
        except Exception:
            self.redis.delete(key)
            raise
        return {"challenge_id": challenge, "expires_in_seconds": 600, "resend_after_seconds": 60}

    def confirm(self, principal, challenge, code):
        user = self.eligible_user(principal)
        valid = self.redis.eval("""
            local expected = redis.call('GET', KEYS[1])
            if not expected then return 0 end
            local n = tonumber(redis.call('GET', KEYS[1] .. ':attempts') or '0')
            if n >= 5 then return 0 end
            if redis.call('INCR', KEYS[1] .. ':attempts') == 1 then redis.call('EXPIRE', KEYS[1] .. ':attempts', 3600) end
            if expected ~= ARGV[1] then return 0 end
            redis.call('DEL', KEYS[1])
            return 1
        """, 1, f"account-delete:{user.id}", self.digest(user, str(challenge), code))
        if not valid:
            raise HTTPException(400, "Code is invalid, expired, or exhausted. Request a new code.")
        self.session.delete(user)
