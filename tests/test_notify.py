import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.models import NotificationEvent
from vhost_cve_monitor.notify import Mailer
from vhost_cve_monitor.notify import NotificationDeliveryError


class NotifyTestCase(unittest.TestCase):
    @staticmethod
    def _html_part(message) -> str:
        for part in message.iter_parts():
            if part.get_content_type() == "text/html":
                payload = part.get_payload(decode=True)
                return payload.decode("utf-8")
        raise AssertionError("HTML part not found")

    def test_build_message_uses_multipart_alternative(self) -> None:
        config = {
            "notifications": {
                "email_to": ["ops@example.net"],
                "email_from": "no-reply@example.net",
                "method": "sendmail",
                "sendmail_path": "/usr/sbin/sendmail",
            }
        }
        mailer = Mailer(config=config, dry_run=True)
        event = NotificationEvent(
            category="test",
            fingerprint="test",
            subject="[Cerberus][HIGH][host] Test notification",
            body="Hostname: host\nSeverity: HIGH\nSummary: test",
            created_at=None,
            metadata={"severity": "HIGH"},
        )

        message = mailer._build_message(event)
        payload = message.as_bytes()

        self.assertEqual(message.get_content_type(), "multipart/alternative")
        self.assertIn(b"Content-Type: multipart/alternative;", payload)
        self.assertIn(b"Content-Type: text/plain", payload)
        self.assertIn(b"Content-Type: text/html", payload)
        self.assertIn(b"Content-Transfer-Encoding: base64", payload)
        self.assertIn(b"Importance: high", payload)

    def test_send_via_smtp_starttls_and_login(self) -> None:
        config = {
            "notifications": {
                "email_to": ["ops@example.net"],
                "email_from": "no-reply@example.net",
                "method": "smtp",
                "smtp_host": "smtp.example.net",
                "smtp_port": 587,
                "smtp_ssl": False,
                "smtp_starttls": True,
                "smtp_username": "cerberus",
                "smtp_password": "secret",
            }
        }
        mailer = Mailer(config=config, dry_run=False)
        event = NotificationEvent(
            category="test",
            fingerprint="test",
            subject="[Cerberus][HIGH][host] Test notification",
            body="Hostname: host\nSeverity: HIGH\nSummary: test",
            created_at=None,
            metadata={"severity": "HIGH"},
        )

        client = MagicMock()
        client.__enter__.return_value = client
        client.__exit__.return_value = False

        with patch("smtplib.SMTP", return_value=client) as smtp_ctor:
            mailer.send(event)

        smtp_ctor.assert_called_once_with("smtp.example.net", 587, timeout=30)
        client.ehlo.assert_called()
        client.starttls.assert_called_once()
        client.login.assert_called_once_with("cerberus", "secret")
        client.send_message.assert_called_once()

    def test_send_via_smtp_ssl_uses_smtp_ssl(self) -> None:
        config = {
            "notifications": {
                "email_to": ["ops@example.net"],
                "email_from": "no-reply@example.net",
                "method": "smtp",
                "smtp_host": "smtp.example.net",
                "smtp_port": 465,
                "smtp_ssl": True,
                "smtp_starttls": False,
                "smtp_username": "",
                "smtp_password": "",
            }
        }
        mailer = Mailer(config=config, dry_run=False)
        event = NotificationEvent(
            category="test",
            fingerprint="test",
            subject="[Cerberus][HIGH][host] Test notification",
            body="Hostname: host\nSeverity: HIGH\nSummary: test",
            created_at=None,
            metadata={"severity": "HIGH"},
        )

        client = MagicMock()
        client.__enter__.return_value = client
        client.__exit__.return_value = False

        with patch("smtplib.SMTP_SSL", return_value=client) as smtp_ssl_ctor:
            mailer.send(event)

        smtp_ssl_ctor.assert_called_once_with("smtp.example.net", 465, timeout=30)
        client.starttls.assert_not_called()
        client.send_message.assert_called_once()

    def test_smtp_password_can_come_from_environment(self) -> None:
        config = {
            "notifications": {
                "email_to": ["ops@example.net"],
                "email_from": "no-reply@example.net",
                "method": "smtp",
                "smtp_host": "smtp.example.net",
                "smtp_port": 587,
                "smtp_ssl": False,
                "smtp_starttls": True,
                "smtp_username": "cerberus",
                "smtp_password": "",
                "smtp_password_env": "CERBERUS_SMTP_PASSWORD",
            }
        }
        mailer = Mailer(config=config, dry_run=False)
        event = NotificationEvent(
            category="test",
            fingerprint="test",
            subject="[Cerberus][HIGH][host] Test notification",
            body="Hostname: host\nSeverity: HIGH\nSummary: test",
            created_at=None,
            metadata={"severity": "HIGH"},
        )

        client = MagicMock()
        client.__enter__.return_value = client
        client.__exit__.return_value = False

        with patch.dict(os.environ, {"CERBERUS_SMTP_PASSWORD": "env-secret"}):
            with patch("smtplib.SMTP", return_value=client):
                mailer.send(event)

        client.login.assert_called_once_with("cerberus", "env-secret")

    def test_sendmail_missing_raises_delivery_error(self) -> None:
        config = {
            "notifications": {
                "email_to": ["ops@example.net"],
                "email_from": "no-reply@example.net",
                "method": "sendmail",
                "sendmail_path": "/nonexistent/sendmail",
            }
        }
        mailer = Mailer(config=config, dry_run=False)
        event = NotificationEvent(
            category="test",
            fingerprint="test",
            subject="[Cerberus][HIGH][host] Test notification",
            body="Hostname: host\nSeverity: HIGH\nSummary: test",
            created_at=None,
            metadata={"severity": "HIGH"},
        )

        with self.assertRaises(NotificationDeliveryError) as ctx:
            mailer.send(event)

        self.assertIn("sendmail not found", str(ctx.exception))

    def test_vulnerability_html_renders_structured_fields_and_bold_advisory(self) -> None:
        config = {
            "notifications": {
                "email_to": ["ops@example.net"],
                "email_from": "no-reply@example.net",
                "method": "sendmail",
                "sendmail_path": "/usr/sbin/sendmail",
            }
        }
        mailer = Mailer(config=config, dry_run=True)
        event = NotificationEvent(
            category="vulnerability",
            fingerprint="test-vuln",
            subject="[Cerberus][HIGH][host] app.example.net jinja2 PYSEC-2024-1",
            body=(
                "Hostname: host\nDate: now\nVhost: app.example.net\nStack: python\nDependency: jinja2\n"
                "Detected version: 3.1.3\nFixed version: >= 3.1.4\nSource file: /tmp/requirements.txt\n"
                "Source line: 10\nCVE / Advisory: PYSEC-2024-1\nSeverity: HIGH\n"
                "Summary: Sandbox escape in Jinja2 environment handling\nRecommendation: upgrade."
            ),
            created_at=None,
            metadata={
                "severity": "HIGH",
                "vhost": "app.example.net",
                "stack": "python",
                "ecosystem": "PyPI",
                "dependency": "jinja2",
                "version": "3.1.3",
                "fixed_version": ">= 3.1.4",
                "vuln_id": "PYSEC-2024-1",
                "advisory_summary": "Sandbox escape in Jinja2 environment handling",
                "source_path": "/tmp/requirements.txt",
                "source_line": 10,
            },
        )

        message = mailer._build_message(event)
        html = self._html_part(message)

        self.assertIn("Advisory", html)
        self.assertIn("<strong>PYSEC-2024-1</strong>", html)
        self.assertIn("Stack / Ecosystem", html)
        self.assertIn("Sandbox escape in Jinja2 environment handling", html)

    def test_digest_html_renders_advisory_summaries_and_breakdown(self) -> None:
        config = {
            "notifications": {
                "email_to": ["ops@example.net"],
                "email_from": "no-reply@example.net",
                "method": "sendmail",
                "sendmail_path": "/usr/sbin/sendmail",
            }
        }
        mailer = Mailer(config=config, dry_run=True)
        event = NotificationEvent(
            category="digest",
            fingerprint="digest",
            subject="[Cerberus][HIGH][host] 2 alerts",
            body=(
                "Hostname: host\nDate: now\nFindings: 2\nHighest severity: HIGH\nBreakdown: 1 HIGH, 1 MEDIUM\n"
                "Summary: new or changed findings were grouped to avoid flooding the destination mailbox.\n\n"
                "HIGH (1)\nRecommendation: prioritize.\n"
            ),
            created_at=type("T", (), {"isoformat": lambda self: "2026-04-10T12:00:00+00:00"})(),
            metadata={
                "severity": "HIGH",
                "hostname": "host",
                "digest_items": [
                    {
                        "vhost": "domain.tld",
                        "stack": "nodejs",
                        "ecosystem": "npm",
                        "dependency": "webpack-dev-server",
                        "version": "4.15.2",
                        "fixed_version": ">= 5.2.1",
                        "severity": "HIGH",
                        "vuln_id": "GHSA-9jgg-88mc-972h",
                        "advisory_summary": "Exposure of webpack-dev-server dev middleware",
                        "source_path": "/tmp/package-lock.json",
                        "source_line": 3286,
                    },
                    {
                        "vhost": "domain.tld",
                        "stack": "nodejs",
                        "ecosystem": "npm",
                        "dependency": "postcss",
                        "version": "7.0.39",
                        "fixed_version": ">= 8.4.31",
                        "severity": "MEDIUM",
                        "vuln_id": "GHSA-7fh5-64p2-3v2j",
                        "advisory_summary": "Line return parsing error in PostCSS",
                        "source_path": "/tmp/package-lock.json",
                        "source_line": 2247,
                    },
                ],
            },
        )

        message = mailer._build_message(event)
        html = self._html_part(message)

        self.assertIn("Breakdown", html)
        self.assertIn("host", html)
        self.assertIn("HIGH (1)", html)
        self.assertIn("MEDIUM (1)", html)
        self.assertIn("<strong>GHSA-9jgg-88mc-972h</strong>", html)
        self.assertIn("Exposure of webpack-dev-server dev middleware", html)


if __name__ == "__main__":
    unittest.main()
