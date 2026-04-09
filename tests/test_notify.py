import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.models import NotificationEvent
from vhost_cve_monitor.notify import Mailer


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


if __name__ == "__main__":
    unittest.main()
