import unittest

from vhost_cve_monitor.scanner import CerberusScanner


class ScannerTestMailTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.config = {
            "scanner": {
                "command_timeout_seconds": 1,
                "repeated_failure_threshold": 3,
                "network_timeout_seconds": 1,
                "scan_interval_minutes": 60,
            },
            "notifications": {
                "email_to": ["ops@example.net"],
                "email_from": "no-reply@example.net",
                "method": "sendmail",
                "sendmail_path": "/usr/sbin/sendmail",
                "max_emails_per_run": 20,
                "summary_only": True,
            },
            "state": {
                "database_path": "/tmp/cerberus-test-mail.db",
                "cve_cache_ttl_hours": 24,
            },
            "nginx": {"sites_enabled_dir": "/tmp/empty"},
            "filters": {},
            "logging": {"level": "INFO", "file": ""},
        }

    def test_send_test_mail_uses_requested_severity_and_category(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)

        event = scanner.send_test_mail(severity="high", category="digest")

        self.assertEqual(event.category, "digest")
        self.assertEqual(event.metadata["severity"], "HIGH")
        self.assertIn("[Cerberus][ALERT][HIGH][", event.subject)
        self.assertIn("Highest severity: HIGH", event.body)


if __name__ == "__main__":
    unittest.main()
