"""Send one explicit SMTP delivery test using the configured email adapter."""

import argparse
from pathlib import Path

from pydantic import EmailStr, TypeAdapter

from app.adapters.smtp_email import SmtpConfiguration, SmtpEmailSender
from app.core.config import Settings
from app.domain.notifications import OutboundEmail


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipient", required=True)
    parser.add_argument("--env-file", type=Path, default=Path("../.env"))
    args = parser.parse_args()
    recipient = str(TypeAdapter(EmailStr).validate_python(args.recipient))
    settings = Settings(_env_file=args.env_file)
    settings.validate_email_configuration()
    SmtpEmailSender(SmtpConfiguration.from_settings(settings)).send(
        OutboundEmail(
            recipient=recipient,
            subject="CVE Monitor local email test",
            text_body=(
                "Your local CVE Monitor SMTP configuration is working. "
                "No vulnerability alert was triggered by this test."
            ),
            html_body=(
                "<p>Your local <strong>CVE Monitor</strong> SMTP configuration is working.</p>"
                "<p>No vulnerability alert was triggered by this test.</p>"
            ),
        )
    )
    print(f"SMTP test accepted for delivery to {recipient}")


if __name__ == "__main__":
    main()
