from html import escape

from app.domain.notifications import (
    DeliveryKind,
    NotificationAlert,
    NotificationBatch,
    OutboundEmail,
)


class NotificationComposer:
    def __init__(self, *, public_app_url: str) -> None:
        self._dashboard_url = f"{public_app_url.rstrip('/')}/dashboard"

    def compose(
        self, *, kind: DeliveryKind, batch: NotificationBatch, recipient: str
    ) -> OutboundEmail:
        count = len(batch.alerts)
        organization_name = _one_line(batch.organization_name)
        if kind is DeliveryKind.REALTIME:
            subject = (
                f"Action required: {count} urgent vulnerability alert"
                f"{'s' if count != 1 else ''}"
            )
            heading = "Urgent vulnerability alert"
            introduction = (
                "These watched products have a critical vulnerability or a vulnerability "
                "known to be actively exploited."
            )
        else:
            subject = f"Daily vulnerability digest: {count} new alert{'s' if count != 1 else ''}"
            heading = "Your daily vulnerability digest"
            introduction = "Here are the new vulnerability matches for your software watchlist."

        subject = f"{subject} — {organization_name}"
        text_items = "\n\n".join(
            _text_alert(index, alert) for index, alert in enumerate(batch.alerts, 1)
        )
        html_items = "".join(_html_alert(alert) for alert in batch.alerts)
        text_body = (
            f"{heading} for {organization_name}\n\n{introduction}\n\n{text_items}\n\n"
            f"Review your dashboard: {self._dashboard_url}\n"
        )
        html_body = (
            "<!doctype html><html><body>"
            f"<h1>{escape(heading)}</h1>"
            f"<p><strong>{escape(organization_name)}</strong></p>"
            f"<p>{escape(introduction)}</p><ul>{html_items}</ul>"
            f'<p><a href="{escape(self._dashboard_url, quote=True)}">Review your dashboard</a></p>'
            "</body></html>"
        )
        return OutboundEmail(
            recipient=recipient,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )


def _text_alert(index: int, alert: NotificationAlert) -> str:
    products = ", ".join(alert.products) if alert.products else "Watched software"
    return (
        f"{index}. {alert.cve_id} — {products}\n"
        f"   {_metrics(alert.cvss_score, alert.epss_score, alert.is_kev)}\n"
        f"   {alert.summary}"
    )


def _html_alert(alert: NotificationAlert) -> str:
    products = ", ".join(alert.products) if alert.products else "Watched software"
    return (
        "<li>"
        f"<p><strong>{escape(alert.cve_id)}</strong> — {escape(products)}<br>"
        f"{escape(_metrics(alert.cvss_score, alert.epss_score, alert.is_kev))}<br>"
        f"{escape(alert.summary or '')}</p>"
        "</li>"
    )


def _metrics(cvss_score: float | None, epss_score: float | None, is_kev: bool) -> str:
    values: list[str] = []
    if cvss_score is not None:
        values.append(f"Severity score {cvss_score:.1f}/10")
    if epss_score is not None:
        values.append(f"Exploitation likelihood {epss_score:.1%}")
    if is_kev:
        values.append("Known active exploitation")
    return " · ".join(values) if values else "Severity data is still being assessed"


def _one_line(value: str) -> str:
    return " ".join(value.splitlines()).strip()
