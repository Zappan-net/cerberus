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
from typing import Dict, List

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
    if event.category == "vulnerability":
        return _html_vulnerability_body(event, severity, color)
    if event.category == "digest":
        return _html_digest_body(event, severity, color)
    return _html_table_body(event, severity, color)


def _html_shell(title: str, category: str, severity: str, color: str, content: str) -> str:
    template = [
        "<html>",
        "<body style=\"margin:0;padding:24px;background:#f8fafc;font-family:Arial,sans-serif;\">",
        "<div style=\"max-width:760px;margin:0 auto;background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;\">",
        "<div style=\"background:{color};padding:18px 24px;color:#ffffff;\">",
        "<div style=\"font-size:12px;letter-spacing:0.08em;font-weight:700;opacity:0.95;\">CERBERUS ALERT</div>",
        "<div style=\"margin-top:6px;font-size:24px;font-weight:700;\">{severity}</div>",
        "<div style=\"margin-top:6px;font-size:14px;opacity:0.95;\">{category}</div>",
        "</div>",
        "<div style=\"padding:20px 24px 24px 24px;\">",
        "<div style=\"font-size:20px;font-weight:700;color:#0f172a;margin-bottom:16px;\">{title}</div>",
        "{content}",
        "</div>",
        "</div>",
        "</body>",
        "</html>",
    ]
    return "\n".join(template).format(
        color=color,
        severity=escape(severity),
        category=escape(category),
        title=escape(title),
        content=content,
    )


def _html_table_body(event: NotificationEvent, severity: str, color: str) -> str:
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
    content = (
        "<table style=\"width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;\">"
        "{rows}"
        "</table>"
    ).format(rows="\n".join(rows))
    return _html_shell(
        event.subject,
        event.category.upper(),
        severity,
        color,
        content,
    )


def _html_value_row(label: str, value: str) -> str:
    return (
        "<div style=\"display:grid;grid-template-columns:180px 1fr;gap:12px;padding:8px 0;border-bottom:1px solid #e5e7eb;\">"
        "<div style=\"font-weight:600;color:#0f172a;\">{}</div>"
        "<div style=\"color:#1f2937;\">{}</div>"
        "</div>"
    ).format(escape(label), value)


def _html_vulnerability_body(event: NotificationEvent, severity: str, color: str) -> str:
    metadata = event.metadata
    advisory_id = escape(str(metadata.get("vuln_id") or "unknown"))
    summary = escape(str(metadata.get("advisory_summary") or "No summary provided by upstream advisory sources."))
    fixed_version = escape(str(metadata.get("fixed_version") or "unknown"))
    source_path = escape(str(metadata.get("source_path") or "unknown"))
    source_line = escape(str(metadata.get("source_line") or "unknown"))
    content = [
        "<div style=\"border:1px solid #e5e7eb;border-radius:12px;padding:16px 18px;background:#ffffff;\">",
        _html_value_row("Target", escape(str(metadata.get("vhost") or "unknown"))),
        _html_value_row("Stack / Ecosystem", escape(
            " / ".join(
                part for part in [str(metadata.get("stack") or "").strip(), str(metadata.get("ecosystem") or "").strip()] if part
            ) or "unknown"
        )),
        _html_value_row("Package", escape(str(metadata.get("dependency") or "unknown"))),
        _html_value_row("Installed version", escape(str(metadata.get("version") or "unknown"))),
        _html_value_row("Fixed version", fixed_version),
        _html_value_row("Severity", escape(severity)),
        _html_value_row("Advisory", "<strong>{}</strong>".format(advisory_id)),
        _html_value_row("Summary", summary),
        _html_value_row("Evidence", "{}:{}".format(source_path, source_line)),
        "</div>",
    ]
    return _html_shell(event.subject, event.category.upper(), severity, color, "\n".join(content))


def _html_digest_body(event: NotificationEvent, severity: str, color: str) -> str:
    metadata = event.metadata
    digest_items: List[Dict[str, object]] = list(metadata.get("digest_items") or [])
    hostname = str(metadata.get("hostname") or "unknown")
    grouped: Dict[str, List[Dict[str, object]]] = {}
    for item in digest_items:
        grouped.setdefault(str(item.get("severity", "UNKNOWN")).upper(), []).append(item)
    severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "WARNING": 2, "LOW": 1, "INFO": 0, "UNKNOWN": -1}
    ordered_severities = sorted(grouped.keys(), key=lambda key: -severity_rank.get(key, -1))
    breakdown = ", ".join("{} {}".format(len(grouped[level]), level) for level in ordered_severities) or "0 UNKNOWN"
    blocks = [
        "<div style=\"border:1px solid #e5e7eb;border-radius:12px;padding:16px 18px;background:#ffffff;margin-bottom:16px;\">",
        _html_value_row("Hostname", escape(hostname)),
        _html_value_row("Date", escape(str(event.created_at.isoformat()))),
        _html_value_row("Findings", escape(str(len(digest_items)))),
        _html_value_row("Highest severity", escape(severity)),
        _html_value_row("Breakdown", escape(breakdown)),
        _html_value_row("Summary", "new or changed findings were grouped to avoid flooding the destination mailbox."),
        "</div>",
    ]
    for level in ordered_severities:
        level_color = SEVERITY_COLORS.get(level, "#475569")
        items = grouped[level]
        blocks.append(
            "<div style=\"border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;background:#ffffff;margin-bottom:16px;\">"
            "<div style=\"background:{color};color:#ffffff;padding:12px 16px;font-weight:700;\">{level} ({count})</div>"
            "<div style=\"padding:16px;\">".format(color=level_color, level=escape(level), count=len(items))
        )
        recommendation = _html_digest_block_recommendation(level, items)
        if recommendation:
            blocks.append(
                "<div style=\"margin-bottom:12px;color:#1f2937;\"><strong>Recommendation:</strong> {}</div>".format(
                    escape(recommendation)
                )
            )
        for item in items:
            stack_context = " / ".join(
                part
                for part in [str(item.get("stack") or "").strip(), str(item.get("ecosystem") or "").strip()]
                if part
            ) or "unknown"
            fixed = str(item.get("fixed_version") or "unknown")
            evidence = escape(str(item.get("source_path") or "unknown"))
            if item.get("source_line"):
                evidence = "{}:{}".format(evidence, escape(str(item.get("source_line"))))
            blocks.extend(
                [
                    "<div style=\"border:1px solid #e5e7eb;border-radius:10px;padding:12px 14px;margin-bottom:12px;\">",
                    _html_value_row("Target", escape(str(item.get("vhost") or "unknown"))),
                    _html_value_row("Stack / Ecosystem", escape(stack_context)),
                    _html_value_row("Package", escape(str(item.get("dependency") or "unknown"))),
                    _html_value_row("Installed version", escape(str(item.get("version") or "unknown"))),
                    _html_value_row("Fixed version", escape(fixed)),
                    _html_value_row("Severity", escape(level)),
                    _html_value_row("Advisory", "<strong>{}</strong>".format(escape(str(item.get("vuln_id") or "unknown")))),
                    _html_value_row("Summary", escape(str(item.get("advisory_summary") or "No summary provided by upstream advisory sources."))),
                    _html_value_row("Evidence", evidence),
                    "</div>",
                ]
            )
        blocks.append("</div></div>")
    return _html_shell(event.subject, event.category.upper(), severity, color, "\n".join(blocks))


def _html_digest_block_recommendation(severity: str, items: List[Dict[str, object]]) -> str:
    ecosystems = {
        str(item.get("ecosystem") or "").lower()
        for item in items
        if str(item.get("ecosystem") or "").strip()
    }
    if len(ecosystems) == 1:
        ecosystem = next(iter(ecosystems))
        if ecosystem == "npm":
            if severity in ("CRITICAL", "HIGH"):
                return (
                    "prioritize these npm dependency upgrades first, apply the fixed versions shown below, review "
                    "package-lock drift carefully, and verify runtime usage before deployment."
                )
            return (
                "schedule these npm dependency upgrades, rebuild package-lock state, and validate runtime usage "
                "before deployment."
            )
        if ecosystem == "pypi":
            if severity in ("CRITICAL", "HIGH"):
                return (
                    "prioritize these Python package updates first, refresh requirements or lockfiles, rerun "
                    "pip-audit, and confirm the affected imports are used at runtime."
                )
            return (
                "schedule these Python package updates, refresh requirements or lockfiles, rerun pip-audit, and "
                "validate runtime usage before deployment."
            )
        if ecosystem == "packagist":
            if severity in ("CRITICAL", "HIGH"):
                return (
                    "prioritize these Composer updates first, review composer.lock changes carefully, and confirm "
                    "the affected packages are used in the deployed application."
                )
            return (
                "schedule these Composer dependency updates, review composer.lock, and validate application "
                "behavior before deployment."
            )
    if severity in ("CRITICAL", "HIGH"):
        return (
            "prioritize the findings in this block first, apply the fixed versions shown below, rebuild the "
            "relevant dependency state, and verify runtime usage before deployment."
        )
    return (
        "schedule the findings in this block for upgrade, apply the fixed versions shown below, rebuild the "
        "relevant dependency state, and validate runtime usage before deployment."
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
