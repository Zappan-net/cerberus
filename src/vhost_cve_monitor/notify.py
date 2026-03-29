from __future__ import annotations

import logging
import smtplib
import socket
import subprocess
from email.policy import SMTP
from html import escape
from email.message import EmailMessage
from typing import Dict

from .models import NotificationEvent

LOGGER = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#dc2626",
    "MEDIUM": "#ea580c",
    "LOW": "#ca8a04",
    "WARNING": "#d97706",
    "INFO": "#2563eb",
    "UNKNOWN": "#475569",
}


def _event_severity(event: NotificationEvent) -> str:
    severity = str(event.metadata.get("severity", "INFO")).upper()
    return severity if severity in SEVERITY_COLORS else "UNKNOWN"


def _html_body(event: NotificationEvent) -> str:
    severity = _event_severity(event)
    color = SEVERITY_COLORS[severity]
    rows = []
    for line in event.body.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            rows.append(
                "<tr>"
                "<td style=\"padding:8px 12px;border-bottom:1px solid #e5e7eb;"
                "font-weight:600;color:#0f172a;vertical-align:top;\">{}</td>"
                "<td style=\"padding:8px 12px;border-bottom:1px solid #e5e7eb;"
                "color:#1f2937;vertical-align:top;\">{}</td>"
                "</tr>".format(escape(key), escape(value))
            )
        else:
            rows.append(
                "<tr><td colspan=\"2\" style=\"padding:8px 12px;border-bottom:1px solid #e5e7eb;"
                "color:#1f2937;\">{}</td></tr>".format(escape(line))
            )
    title = escape(event.subject)
    category = escape(event.category.upper())
    template = [
        "<html>",
        "<body style=\"margin:0;padding:24px;background:#f8fafc;font-family:Arial,sans-serif;\">",
        "<div style=\"max-width:760px;margin:0 auto;background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;\">",
        "<div style=\"background:{color};padding:18px 24px;color:#ffffff;\">",
        "<div style=\"font-size:12px;letter-spacing:0.08em;font-weight:700;opacity:0.95;\">CERBERUS ALERT</div>",
        "<div style=\"margin-top:6px;font-size:24px;font-weight:700;\">{severity}</div>",
        "<div style=\"margin-top:6px;font-size:14px;opacity:0.95;\">{category}</div>",
        "</div>",
        "<div style=\"padding:20px 24px 8px 24px;\">",
        "<div style=\"font-size:20px;font-weight:700;color:#0f172a;\">{title}</div>",
        "</div>",
        "<div style=\"padding:0 24px 24px 24px;\">",
        "<table style=\"width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;\">",
        "{rows}",
        "</table>",
        "</div>",
        "</div>",
        "</body>",
        "</html>",
    ]
    return "\n".join(template).format(
        color=color,
        severity=severity,
        category=category,
        title=title,
        rows="\n".join(rows),
    )


class Mailer:
    def __init__(self, config: Dict, dry_run: bool = False):
        self.config = config
        self.dry_run = dry_run

    def _build_message(self, event: NotificationEvent) -> EmailMessage:
        recipients = self.config["notifications"]["email_to"]
        sender = self.config["notifications"]["email_from"]
        message = EmailMessage()
        message["From"] = sender
        message["To"] = ", ".join(recipients)
        message["Subject"] = event.subject
        message["X-Cerberus-Host"] = socket.gethostname()
        message["X-Cerberus-Severity"] = _event_severity(event)
        message["X-Priority"] = "1" if _event_severity(event) in ("CRITICAL", "HIGH") else "3"
        message["Priority"] = "urgent" if _event_severity(event) in ("CRITICAL", "HIGH") else "normal"
        message["Importance"] = "high" if _event_severity(event) in ("CRITICAL", "HIGH") else "normal"
        message.set_content(event.body.encode("utf-8"), maintype="text", subtype="plain", cte="base64")
        message.add_alternative(
            _html_body(event).encode("utf-8"),
            maintype="text",
            subtype="html",
            cte="base64",
        )
        return message

    def send(self, event: NotificationEvent) -> None:
        recipients = self.config["notifications"]["email_to"]
        message = self._build_message(event)
        if self.dry_run:
            LOGGER.info("Dry-run mail to %s with subject %s", ", ".join(recipients), event.subject)
            LOGGER.debug("Dry-run mail content:\n%s", message)
            return
        method = self.config["notifications"].get("method", "sendmail")
        if method == "smtp":
            host = self.config["notifications"]["smtp_host"]
            port = int(self.config["notifications"]["smtp_port"])
            LOGGER.info("Sending mail via SMTP to %s:%s", host, port)
            with smtplib.SMTP(host, port, timeout=30) as client:
                client.send_message(message)
            LOGGER.info("Mail sent to %s", ", ".join(recipients))
            return
        sendmail_path = self.config["notifications"]["sendmail_path"]
        LOGGER.info("Sending mail via sendmail using %s", sendmail_path)
        payload = message.as_bytes(policy=SMTP)
        process = subprocess.run(
            [sendmail_path, "-t", "-oi"],
            input=payload,
            capture_output=True,
            check=False,
        )
        if process.returncode != 0:
            raise RuntimeError(f"sendmail failed: {process.stderr.decode('utf-8', errors='replace').strip()}")
        LOGGER.info("Mail sent to %s", ", ".join(recipients))
