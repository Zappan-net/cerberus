import unittest
from datetime import datetime, timezone

from vhost_cve_monitor.scanner import CerberusScanner
from vhost_cve_monitor.models import NotificationEvent


class ScannerDigestTestCase(unittest.TestCase):
    def test_digest_deduplicates_and_keeps_highest_severity(self) -> None:
        config = {
            "scanner": {
                "command_timeout_seconds": 1,
                "repeated_failure_threshold": 3,
                "network_timeout_seconds": 1,
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
                "database_path": "/tmp/cerberus-test-digest.db",
                "cve_cache_ttl_hours": 24,
            },
            "nginx": {"sites_enabled_dir": "/tmp/empty"},
            "filters": {},
            "logging": {"level": "INFO", "file": ""},
        }
        scanner = CerberusScanner(config=config, dry_run=True, allow_network=False)
        event = NotificationEvent(
            category="vulnerability",
            fingerprint="x",
            subject="[Cerberus][ALERT][UNKNOWN][host] admin.zap.one serialize-javascript GHSA-1",
            body="",
            created_at=datetime.now(timezone.utc),
            metadata={
                "vhost": "admin. zap.one",
                "dependency": "serialize-javascript",
                "version": "6.0.2",
                "vuln_id": "GHSA-1",
                "severity": "UNKNOWN",
                "source_path": "/tmp/package-lock.json",
                "source_line": 42,
            },
        )
        warning_event = NotificationEvent(
            category="scan-failure",
            fingerprint="y",
            subject="[Cerberus][ALERT][WARNING][host] admin.zap.one repeated scan failure",
            body="",
            created_at=datetime.now(timezone.utc),
            metadata={
                "scope": "admin.zap.one",
                "reason": "pip_audit_unavailable",
                "severity": "WARNING",
            },
        )

        digest = scanner._build_digest_notification([event, event, warning_event], subject_all=True)

        self.assertIn("Highest severity: WARNING", digest.body)
        self.assertIn("admin.zap.one | serialize-javascript 6.0.2 | GHSA-1 [/tmp/package-lock.json:42]", digest.body)
        self.assertEqual(digest.body.count("serialize-javascript 6.0.2"), 1)


if __name__ == "__main__":
    unittest.main()
