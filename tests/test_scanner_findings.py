import os
import socket
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.models import AuditIssue, Dependency, Vulnerability
from vhost_cve_monitor.scanner import CerberusScanner


class ScannerFindingsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
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
                "database_path": str(Path(self.tmp.name) / "state.db"),
                "cve_cache_ttl_hours": 24,
            },
            "nginx": {"sites_enabled_dir": "/tmp/empty"},
            "filters": {},
            "logging": {"level": "INFO", "file": ""},
        }

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_same_finding_across_two_vhosts_keeps_both_hosts_and_best_severity(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)
        dependency = Dependency(
            ecosystem="npm",
            name="nth-check",
            version="1.0.2",
            source="/home/webserv/zap-and-rok/package-lock.json",
            source_line=17872,
        )
        medium_vuln = Vulnerability(
            vuln_id="GHSA-rp65-9cf3-cjxr",
            source="runtime-audit",
            severity="MEDIUM",
            summary="Inefficient regular expression complexity",
            details="",
            published=None,
            modified=None,
            package_name="nth-check",
            ecosystem="npm",
            affected_version="1.0.2",
            fixed_version=">= 2.0.1",
            aliases=[],
            references=[],
        )
        unknown_vuln = Vulnerability(
            vuln_id="GHSA-rp65-9cf3-cjxr",
            source="OSV",
            severity="UNKNOWN",
            summary="Inefficient regular expression complexity",
            details="",
            published=None,
            modified=None,
            package_name="nth-check",
            ecosystem="npm",
            affected_version="1.0.2",
            fixed_version=None,
            aliases=[],
            references=[],
        )
        occurrences = [
            {"vhost": "domain.tld", "stack": "nodejs", "issue": AuditIssue(dependency, medium_vuln, "npm-audit")},
            {"vhost": "admin.domain.tld", "stack": "nodejs", "issue": AuditIssue(dependency, unknown_vuln, "osv-cache")},
        ]

        notifications = scanner._build_issue_notifications(occurrences)
        digest = scanner._build_digest_notification(notifications, subject_all=True)

        self.assertEqual(len(notifications), 2)
        self.assertTrue(all(item.metadata["severity"] == "MEDIUM" for item in notifications))
        self.assertIn("[Cerberus][MEDIUM][{}] 2 alerts".format(socket.gethostname()), digest.subject)
        self.assertIn("- domain.tld | nodejs / npm | [/home/webserv/zap-and-rok/package-lock.json:17872]", digest.body)
        self.assertIn("- admin.domain.tld | nodejs / npm | [/home/webserv/zap-and-rok/package-lock.json:17872]", digest.body)
        self.assertIn("  [MEDIUM] nth-check 1.0.2 -> fixed in >= 2.0.1 | GHSA-rp65-9cf3-cjxr", digest.body)

    def test_single_alert_subject_is_compact_and_includes_fixed_version_and_recommendation(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)
        dependency = Dependency(
            ecosystem="Packagist",
            name="symfony/http-foundation",
            version="5.4.0",
            source="/srv/app/composer.lock",
            source_line=20,
        )
        vuln = Vulnerability(
            vuln_id="CVE-2026-1000",
            source="OSV",
            severity="HIGH",
            summary="Example advisory",
            details="",
            published=None,
            modified=None,
            package_name=dependency.name,
            ecosystem=dependency.ecosystem,
            affected_version=dependency.version,
            fixed_version=">= 5.4.46",
            aliases=["GHSA-test-1234"],
            references=[],
        )
        notifications = scanner._build_issue_notifications(
            [{"vhost": "app.example.net", "stack": "php-composer", "issue": AuditIssue(dependency, vuln, "osv-cache")}]
        )

        self.assertEqual(len(notifications), 1)
        self.assertIn(
            "[Cerberus][HIGH][{}] app.example.net symfony/http-foundation CVE-2026-1000".format(socket.gethostname()),
            notifications[0].subject,
        )
        self.assertIn("Fixed version: >= 5.4.46", notifications[0].body)
        self.assertIn("composer update symfony/http-foundation", notifications[0].body)
        self.assertIn("used at runtime or only during build/test", notifications[0].body)
        self.assertIn("Summary: Example advisory", notifications[0].body)

    def test_new_findings_are_all_notified_when_they_are_distinct(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)
        occurrences = []
        for dependency_name, version, vuln_id, summary, fixed_version, line in [
            ("nth-check", "1.0.2", "GHSA-rp65-9cf3-cjxr", "Inefficient Regular Expression Complexity in nth-check", ">= 2.0.1", 17839),
            ("postcss", "7.0.39", "GHSA-7fh5-64p2-3v2j", "Line return parsing error in PostCSS", ">= 8.4.31", 2247),
            ("webpack-dev-server", "4.15.2", "GHSA-9jgg-88mc-972h", "Exposure of webpack-dev-server dev middleware", ">= 5.2.1", 3286),
        ]:
            dependency = Dependency("npm", dependency_name, version, "/home/webserv/zap-and-rok/package-lock.json", line)
            vuln = Vulnerability(
                vuln_id=vuln_id,
                source="runtime-audit",
                severity="HIGH" if dependency_name != "postcss" else "MEDIUM",
                summary=summary,
                details="",
                published=None,
                modified=None,
                package_name=dependency.name,
                ecosystem=dependency.ecosystem,
                affected_version=dependency.version,
                fixed_version=fixed_version,
                aliases=[],
                references=[],
            )
            occurrences.append({"vhost": "domain.tld", "stack": "nodejs", "issue": AuditIssue(dependency, vuln, "npm-audit")})

        notifications = scanner._build_issue_notifications(occurrences)
        digest = scanner._build_digest_notification(notifications, subject_all=True)

        self.assertEqual(len(notifications), 3)
        self.assertIn("nth-check", digest.body)
        self.assertIn("postcss", digest.body)
        self.assertIn("webpack-dev-server", digest.body)
        self.assertIn("Inefficient Regular Expression Complexity in nth-check", digest.body)
        self.assertIn("Line return parsing error in PostCSS", digest.body)
        self.assertIn("Exposure of webpack-dev-server dev middleware", digest.body)


if __name__ == "__main__":
    unittest.main()
