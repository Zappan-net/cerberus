import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.models import NotificationEvent
from vhost_cve_monitor.notify import Mailer
from vhost_cve_monitor.notify import NotificationDeliveryError


class NotifyTestCase(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
