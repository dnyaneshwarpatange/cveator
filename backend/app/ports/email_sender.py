from typing import Protocol

from app.domain.notifications import OutboundEmail


class EmailSender(Protocol):
    """Vendor-neutral boundary for transactional email delivery."""

    def send(self, message: OutboundEmail) -> None:
        """Submit one message or raise when the SMTP server rejects it."""
        ...
