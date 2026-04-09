from __future__ import annotations

import logging
import os
import shutil
import smtplib
import socket
import ssl
import subprocess
from email.policy import SMTP
from html import escape
from email.message import EmailMessage
from typing import Dict

from .models import NotificationEvent

LOGGER = logging.getLogger(__name__)


class NotificationDeliveryError(RuntimeError):
    """Raised when Cerberus cannot hand off a notification to the configured mail transport."""

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
            self._send_via_smtp(message, recipients)
            LOGGER.info("Mail sent to %s", ", ".join(recipients))
            return
        sendmail_path = self.config["notifications"]["sendmail_path"]
        LOGGER.info("Sending mail via sendmail using %s", sendmail_path)
        resolved_sendmail = shutil.which(sendmail_path) if os.sep not in sendmail_path else sendmail_path
        if not resolved_sendmail or not os.path.exists(resolved_sendmail):
            raise NotificationDeliveryError("sendmail not found at {}".format(sendmail_path))
        payload = message.as_bytes(policy=SMTP)
        try:
            process = subprocess.run(
                [resolved_sendmail, "-t", "-oi"],
                input=payload,
                capture_output=True,
                check=False,
            )
        except OSError as exc:
            raise NotificationDeliveryError("sendmail delivery failed: {}".format(exc)) from exc
        if process.returncode != 0:
            raise NotificationDeliveryError(
                "sendmail failed: {}".format(process.stderr.decode("utf-8", errors="replace").strip())
            )
        LOGGER.info("Mail sent to %s", ", ".join(recipients))

    def _send_via_smtp(self, message: EmailMessage, recipients) -> None:
        notifications = self.config["notifications"]
        host = notifications["smtp_host"]
        port = int(notifications["smtp_port"])
        use_ssl = bool(notifications.get("smtp_ssl"))
        use_starttls = bool(notifications.get("smtp_starttls"))
        username = str(notifications.get("smtp_username") or "").strip()
        password = self._smtp_password()
        LOGGER.info(
            "Sending mail via SMTP to %s:%s (ssl=%s, starttls=%s, auth=%s)",
            host,
            port,
            use_ssl,
            use_starttls,
            bool(username),
        )
        if use_ssl and use_starttls:
            raise RuntimeError("smtp_ssl and smtp_starttls cannot both be enabled")
        if username and not password:
            raise RuntimeError("SMTP authentication requires a password or smtp_password_env")
        client_factory = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
        context = ssl.create_default_context()
        try:
            with client_factory(host, port, timeout=30) as client:
                if not use_ssl:
                    client.ehlo()
                    if use_starttls:
                        client.starttls(context=context)
                        client.ehlo()
                if username:
                    client.login(username, password)
                client.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            raise NotificationDeliveryError("SMTP delivery failed: {}".format(exc)) from exc

    def _smtp_password(self) -> str:
        notifications = self.config["notifications"]
        env_name = str(notifications.get("smtp_password_env") or "").strip()
        if env_name:
            return os.environ.get(env_name, "")
        return str(notifications.get("smtp_password") or "")
