import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from typing import Literal

from app.core.config import Settings
from app.core.time import utc_now
from app.domain.notifications import OutboundEmail


@dataclass(frozen=True, slots=True)
class SmtpConfiguration:
    host: str
    port: int
    security: Literal["none", "starttls", "tls"]
    from_address: str
    from_name: str
    username: str | None = None
    password: str | None = None
    timeout_seconds: float = 15

    @classmethod
    def from_settings(cls, settings: Settings) -> "SmtpConfiguration":
        return cls(
            host=settings.smtp_host,
            port=settings.smtp_port,
            security=settings.smtp_security,
            from_address=settings.email_from_address,
            from_name=settings.email_from_name,
            username=settings.smtp_username or None,
            password=(
                settings.smtp_password.get_secret_value() if settings.smtp_password else None
            ),
            timeout_seconds=settings.smtp_timeout_seconds,
        )


class SmtpEmailSender:
    def __init__(self, configuration: SmtpConfiguration) -> None:
        self._configuration = configuration

    def send(self, message: OutboundEmail) -> None:
        _reject_header_injection(message.recipient, "recipient")
        _reject_header_injection(message.subject, "subject")

        email = EmailMessage()
        email["From"] = (
            f"{self._configuration.from_name} <{self._configuration.from_address}>"
            if self._configuration.from_name
            else self._configuration.from_address
        )
        email["To"] = message.recipient
        email["Subject"] = message.subject
        email["Date"] = format_datetime(utc_now())
        message_id_domain = self._configuration.from_address.rpartition("@")[2] or None
        email["Message-ID"] = make_msgid(domain=message_id_domain)
        email.set_content(message.text_body)
        email.add_alternative(message.html_body, subtype="html")

        client = self._connect()
        try:
            if self._configuration.security == "starttls":
                client.ehlo()
                client.starttls(context=ssl.create_default_context())
                client.ehlo()
            if self._configuration.username:
                client.login(
                    self._configuration.username,
                    self._configuration.password or "",
                )
            client.send_message(
                email,
                from_addr=self._configuration.from_address,
                to_addrs=[message.recipient],
            )
        finally:
            try:
                client.quit()
            except (OSError, smtplib.SMTPException):
                client.close()

    def _connect(self) -> smtplib.SMTP:
        if self._configuration.security == "tls":
            return smtplib.SMTP_SSL(
                self._configuration.host,
                self._configuration.port,
                timeout=self._configuration.timeout_seconds,
                context=ssl.create_default_context(),
            )
        return smtplib.SMTP(
            self._configuration.host,
            self._configuration.port,
            timeout=self._configuration.timeout_seconds,
        )


def _reject_header_injection(value: str, field: str) -> None:
    if "\r" in value or "\n" in value:
        raise ValueError(f"Email {field} contains a newline")
