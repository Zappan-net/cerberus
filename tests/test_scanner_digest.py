import os
import sys
import unittest
from datetime import datetime, timezone
import socket

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.scanner import CerberusScanner
from vhost_cve_monitor.models import NotificationEvent


class ScannerDigestTestCase(unittest.TestCase):
    def _build_scanner(self) -> CerberusScanner:
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
        return CerberusScanner(config=config, dry_run=True, allow_network=False)

    def test_digest_deduplicates_and_keeps_highest_severity(self) -> None:
        scanner = self._build_scanner()
        event = NotificationEvent(
            category="vulnerability",
            fingerprint="x",
            subject="[Cerberus][UNKNOWN][host] admin.domain.tld serialize-javascript GHSA-1",
            body="",
            created_at=datetime.now(timezone.utc),
            metadata={
                "vhost": "admin.domain.tld",
                "dependency": "serialize-javascript",
                "version": "6.0.2",
                "vuln_id": "GHSA-1",
                "severity": "UNKNOWN",
                "fixed_version": ">= 6.0.3",
                "source_path": "/tmp/package-lock.json",
                "source_line": 42,
                "ecosystem": "npm",
                "stack": "nodejs",
                "advisory_summary": "Remote code execution in serialize-javascript",
            },
        )
        warning_event = NotificationEvent(
            category="scan-failure",
            fingerprint="y",
            subject="[Cerberus][WARNING][host] admin.domain.tld repeated scan failure",
            body="",
            created_at=datetime.now(timezone.utc),
            metadata={
                "scope": "admin.domain.tld",
                "reason": "pip_audit_unavailable",
                "severity": "WARNING",
            },
        )

        digest = scanner._build_digest_notification([event, event, warning_event], subject_all=True)

        self.assertIn("Highest severity: WARNING", digest.body)
        self.assertIn("Breakdown: 1 WARNING, 1 UNKNOWN", digest.body)
        self.assertIn("Summary: new or changed findings were grouped to avoid flooding the destination mailbox.", digest.body)
        self.assertIn("WARNING (1)", digest.body)
        self.assertIn("UNKNOWN (1)", digest.body)
        self.assertIn("- admin.domain.tld | nodejs / npm | [/tmp/package-lock.json:42]", digest.body)
        self.assertIn("  [UNKNOWN] serialize-javascript 6.0.2 -> fixed in >= 6.0.3 | GHSA-1", digest.body)
        self.assertIn("  Summary: Remote code execution in serialize-javascript", digest.body)
        self.assertEqual(digest.body.count("serialize-javascript 6.0.2"), 1)
        self.assertEqual(digest.subject, "[Cerberus][WARNING][{}] 2 alerts".format(socket.gethostname()))

    def test_digest_subject_uses_highest_known_severity_after_merge(self) -> None:
        scanner = self._build_scanner()
        unknown = NotificationEvent(
            category="vulnerability",
            fingerprint="x1",
            subject="[Cerberus][UNKNOWN][host] domain.tld multer GHSA-1",
            body="",
            created_at=datetime.now(timezone.utc),
            metadata={
                "vhost": "domain.tld",
                "dependency": "multer",
                "version": "1.4.5",
                "vuln_id": "GHSA-1",
                "severity": "UNKNOWN",
                "source_path": "/tmp/package-lock.json",
                "source_line": 21,
                "ecosystem": "npm",
                "stack": "nodejs",
                "advisory_summary": "First advisory variant",
            },
        )
        high = NotificationEvent(
            category="vulnerability",
            fingerprint="x2",
            subject="[Cerberus][HIGH][host] domain.tld multer GHSA-1",
            body="",
            created_at=datetime.now(timezone.utc),
            metadata={
                "vhost": "domain.tld",
                "dependency": "multer",
                "version": "1.4.5",
                "vuln_id": "GHSA-1",
                "severity": "HIGH",
                "source_path": "/tmp/package-lock.json",
                "source_line": 21,
                "ecosystem": "npm",
                "stack": "nodejs",
                "advisory_summary": "High severity advisory variant",
            },
        )

        digest = scanner._build_digest_notification([unknown, high], subject_all=True)

        self.assertEqual(digest.subject, "[Cerberus][HIGH][{}] 1 alerts".format(socket.gethostname()))
        self.assertIn("Highest severity: HIGH", digest.body)
        self.assertEqual(digest.metadata["severity"], "HIGH")

    def test_digest_subject_can_remain_unknown_if_all_findings_are_unknown(self) -> None:
        scanner = self._build_scanner()
        unknown = NotificationEvent(
            category="vulnerability",
            fingerprint="x3",
            subject="[Cerberus][UNKNOWN][host] domain.tld nth-check GHSA-2",
            body="",
            created_at=datetime.now(timezone.utc),
            metadata={
                "vhost": "domain.tld",
                "dependency": "nth-check",
                "version": "1.0.2",
                "vuln_id": "GHSA-2",
                "severity": "UNKNOWN",
                "source_path": "/tmp/package-lock.json",
                "source_line": 99,
                "ecosystem": "npm",
                "stack": "nodejs",
                "advisory_summary": "Unknown severity advisory",
            },
        )

        digest = scanner._build_digest_notification([unknown], subject_all=True)

        self.assertEqual(digest.subject, "[Cerberus][UNKNOWN][{}] 1 alerts".format(socket.gethostname()))
        self.assertIn("Highest severity: UNKNOWN", digest.body)
        self.assertEqual(digest.metadata["severity"], "UNKNOWN")

    def test_digest_subject_and_body_severity_always_match(self) -> None:
        scanner = self._build_scanner()
        events = [
            NotificationEvent(
                category="vulnerability",
                fingerprint="x4",
                subject="[Cerberus][UNKNOWN][host] domain.tld postcss GHSA-3",
                body="",
                created_at=datetime.now(timezone.utc),
                metadata={
                    "vhost": "domain.tld",
                    "dependency": "postcss",
                    "version": "7.0.39",
                    "vuln_id": "GHSA-3",
                    "severity": "UNKNOWN",
                    "source_path": "/tmp/package-lock.json",
                    "source_line": 2247,
                    "ecosystem": "npm",
                    "stack": "nodejs",
                    "advisory_summary": "Lower quality advisory metadata",
                },
            ),
            NotificationEvent(
                category="vulnerability",
                fingerprint="x5",
                subject="[Cerberus][HIGH][host] domain.tld postcss GHSA-3",
                body="",
                created_at=datetime.now(timezone.utc),
                metadata={
                    "vhost": "domain.tld",
                    "dependency": "postcss",
                    "version": "7.0.39",
                    "vuln_id": "GHSA-3",
                    "severity": "HIGH",
                    "source_path": "/tmp/package-lock.json",
                    "source_line": 2247,
                    "ecosystem": "npm",
                    "stack": "nodejs",
                    "advisory_summary": "Proper high severity summary",
                },
            ),
        ]

        digest = scanner._build_digest_notification(events, subject_all=True)

        self.assertTrue(digest.subject.startswith("[Cerberus][HIGH]"))
        self.assertIn("Highest severity: HIGH", digest.body)
        self.assertEqual(digest.metadata["severity"], "HIGH")

    def test_digest_renders_severity_blocks_and_counts(self) -> None:
        scanner = self._build_scanner()
        high_event = NotificationEvent(
            category="vulnerability",
            fingerprint="h1",
            subject="[Cerberus][HIGH][host] domain.tld webpack-dev-server GHSA-H",
            body="",
            created_at=datetime.now(timezone.utc),
            metadata={
                "vhost": "domain.tld",
                "dependency": "webpack-dev-server",
                "version": "4.15.2",
                "vuln_id": "GHSA-H",
                "severity": "HIGH",
                "fixed_version": ">= 5.2.1",
                "source_path": "/tmp/package-lock.json",
                "source_line": 3286,
                "ecosystem": "npm",
                "stack": "nodejs",
                "advisory_summary": "Exposure of webpack-dev-server dev middleware",
            },
        )
        medium_event = NotificationEvent(
            category="vulnerability",
            fingerprint="m1",
            subject="[Cerberus][MEDIUM][host] domain.tld postcss GHSA-M",
            body="",
            created_at=datetime.now(timezone.utc),
            metadata={
                "vhost": "domain.tld",
                "dependency": "postcss",
                "version": "7.0.39",
                "vuln_id": "GHSA-M",
                "severity": "MEDIUM",
                "fixed_version": ">= 8.4.31",
                "source_path": "/tmp/package-lock.json",
                "source_line": 2247,
                "ecosystem": "npm",
                "stack": "nodejs",
                "advisory_summary": "Line return parsing error in PostCSS",
            },
        )
        medium_event_2 = NotificationEvent(
            category="vulnerability",
            fingerprint="m2",
            subject="[Cerberus][MEDIUM][host] admin.domain.tld nth-check GHSA-M2",
            body="",
            created_at=datetime.now(timezone.utc),
            metadata={
                "vhost": "admin.domain.tld",
                "dependency": "nth-check",
                "version": "1.0.2",
                "vuln_id": "GHSA-M2",
                "severity": "MEDIUM",
                "fixed_version": ">= 2.0.1",
                "source_path": "/tmp/package-lock.json",
                "source_line": 17872,
                "ecosystem": "npm",
                "stack": "nodejs",
                "advisory_summary": "Inefficient Regular Expression Complexity in nth-check",
            },
        )

        digest = scanner._build_digest_notification([medium_event, high_event, medium_event_2], subject_all=True)

        self.assertEqual(digest.subject, "[Cerberus][HIGH][{}] 3 alerts".format(socket.gethostname()))
        self.assertIn("Findings: 3", digest.body)
        self.assertIn("Highest severity: HIGH", digest.body)
        self.assertIn("Breakdown: 1 HIGH, 2 MEDIUM", digest.body)
        self.assertLess(digest.body.index("HIGH (1)"), digest.body.index("MEDIUM (2)"))
        self.assertIn("Recommendation: prioritize these npm dependency upgrades first", digest.body)
        self.assertIn("Recommendation: schedule these npm dependency upgrades", digest.body)
        self.assertIn("- domain.tld | nodejs / npm | [/tmp/package-lock.json:3286]", digest.body)
        self.assertIn("  [HIGH] webpack-dev-server 4.15.2 -> fixed in >= 5.2.1 | GHSA-H", digest.body)
        self.assertIn("  Summary: Exposure of webpack-dev-server dev middleware", digest.body)
        self.assertIn("- domain.tld | nodejs / npm | [/tmp/package-lock.json:2247]", digest.body)
        self.assertIn("  [MEDIUM] postcss 7.0.39 -> fixed in >= 8.4.31 | GHSA-M", digest.body)
        self.assertIn("  Summary: Line return parsing error in PostCSS", digest.body)
        self.assertIn("- admin.domain.tld | nodejs / npm | [/tmp/package-lock.json:17872]", digest.body)
        self.assertIn("  [MEDIUM] nth-check 1.0.2 -> fixed in >= 2.0.1 | GHSA-M2", digest.body)
        self.assertIn("  Summary: Inefficient Regular Expression Complexity in nth-check", digest.body)


if __name__ == "__main__":
    unittest.main()
