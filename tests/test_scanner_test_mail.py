import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.notify import Mailer
from vhost_cve_monitor.scanner import CerberusScanner


class ScannerTestMailTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
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
                "database_path": os.path.join(self.tmp.name, "state.db"),
                "cve_cache_ttl_hours": 24,
            },
            "nginx": {"sites_enabled_dir": "/tmp/empty"},
            "filters": {},
            "logging": {"level": "INFO", "file": ""},
        }

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_send_test_mail_uses_requested_severity_and_category(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)

        event = scanner.send_test_mail(severity="high", category="digest")

        self.assertEqual(event.category, "digest")
        self.assertEqual(event.metadata["severity"], "HIGH")
        self.assertIn("[Cerberus][HIGH][", event.subject)
        self.assertIn("Highest severity: HIGH", event.body)

    def test_send_custom_test_mail_renders_stack_aware_recommendation(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)

        event = scanner.send_custom_test_mail(
            severity="high",
            category="vulnerability",
            stack="nodejs",
            package_name="lodash",
            installed_version="4.17.23",
            fixed_version=">= 4.17.24",
            advisory_id="GHSA-35jh-r3h4-6jhm",
            vhost="app.example.net",
            source_file="/srv/app/package-lock.json",
            source_line=3726,
        )

        self.assertEqual(event.category, "vulnerability")
        self.assertEqual(event.metadata["ecosystem"], "npm")
        self.assertIn("[Cerberus][HIGH][", event.subject)
        self.assertIn("app.example.net lodash GHSA-35jh-r3h4-6jhm", event.subject)
        self.assertIn("Fixed version: >= 4.17.24", event.body)
        self.assertIn("npm install lodash@", event.body)
        self.assertIn("used at runtime or only during build/test", event.body)
        self.assertEqual(event.metadata["vhost"], "app.example.net")
        self.assertEqual(event.metadata["source_path"], "/srv/app/package-lock.json")
        self.assertEqual(event.metadata["source_line"], 3726)
        self.assertEqual(
            event.metadata["advisory_summary"],
            "simulated vulnerability notification from vhost-cve-monitor",
        )

        message = Mailer(config=self.config, dry_run=True)._build_message(event)
        html_part = None
        for part in message.iter_parts():
            if part.get_content_type() == "text/html":
                html_part = part.get_payload(decode=True).decode("utf-8")
                break
        self.assertIsNotNone(html_part)
        self.assertIn("app.example.net", html_part)
        self.assertIn("GHSA-35jh-r3h4-6jhm", html_part)
        self.assertIn("/srv/app/package-lock.json:3726", html_part)

    def test_send_test_mail_supports_internal_error_category(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)

        event = scanner.send_custom_test_mail(category="internal-error", severity="high")

        self.assertEqual(event.category, "internal-error")
        self.assertIn("internal error during test-mail", event.subject)
        self.assertIn("report it on https://github.com/Zappan-net/cerberus/issues", event.body)

    def test_internal_error_notifications_are_not_wrapped_into_digest(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)
        internal = scanner.send_custom_test_mail(category="internal-error", severity="high")
        digest = scanner.send_test_mail(severity="medium", category="digest")

        prepared = scanner._prepare_notifications_for_delivery([internal, digest])

        self.assertEqual(prepared[0].category, "internal-error")
        self.assertEqual(prepared[1].category, "digest")

    def test_report_internal_error_deduplicates_identical_failures(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)

        first = scanner.report_internal_error("scan-once", RuntimeError("boom"))
        second = scanner.report_internal_error("scan-once", RuntimeError("boom"))

        self.assertIsNotNone(first)
        self.assertIsNone(second)


if __name__ == "__main__":
    unittest.main()
