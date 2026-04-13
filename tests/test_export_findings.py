import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.models import AuditIssue, Dependency, StackMatch, Vulnerability, VhostConfig, StackScanResult
from vhost_cve_monitor.scanner import CerberusScanner


class ExportFindingsTestCase(unittest.TestCase):
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

    def test_export_findings_backfills_snapshot_without_notifications(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)
        dependency = Dependency(
            ecosystem="npm",
            name="webpack-dev-server",
            version="4.15.2",
            source="/srv/app/package-lock.json",
            source_line=3286,
        )
        vulnerability = Vulnerability(
            vuln_id="GHSA-9jgg-88mc-972h",
            source="runtime-audit",
            severity="HIGH",
            summary="Exposure of webpack-dev-server dev middleware",
            details="",
            published=None,
            modified=None,
            package_name="webpack-dev-server",
            ecosystem="npm",
            affected_version="4.15.2",
            fixed_version=">= 5.2.1",
            affected_range="<5.2.1",
            aliases=[],
            references=[],
        )
        vhost = VhostConfig(file_path="/etc/nginx/sites-enabled/app.conf", server_names=["app.domain.tld"])
        stack_match = StackMatch(stack_name="nodejs", confidence="high", reasons=["package-lock.json"], root_path="/srv/app")
        stack_result = StackScanResult(
            stack=stack_match,
            dependencies=[dependency],
            issues=[AuditIssue(dependency, vulnerability, "npm-audit")],
            failures=[],
        )

        with patch("vhost_cve_monitor.scanner.load_vhosts", return_value=[vhost]), patch(
            "vhost_cve_monitor.scanner.detect_stacks", return_value=[stack_match]
        ), patch("vhost_cve_monitor.scanner.scan_stack", return_value=stack_result), patch.object(
            scanner.mailer, "send"
        ) as send_mock:
            exported = scanner.export_findings()

        send_mock.assert_not_called()
        self.assertEqual(exported["findings_count"], 1)
        self.assertEqual(exported["breakdown"], {"HIGH": 1})
        self.assertEqual(exported["findings"][0]["dependency"], "webpack-dev-server")
        self.assertEqual(exported["findings"][0]["vhost"], "app.domain.tld")

    def test_scan_once_materializes_current_findings_for_export(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)
        dependency = Dependency(
            ecosystem="npm",
            name="postcss",
            version="7.0.39",
            source="/srv/app/package-lock.json",
            source_line=2247,
        )
        vulnerability = Vulnerability(
            vuln_id="GHSA-7fh5-64p2-3v2j",
            source="runtime-audit",
            severity="MEDIUM",
            summary="Line return parsing error in PostCSS",
            details="",
            published=None,
            modified=None,
            package_name="postcss",
            ecosystem="npm",
            affected_version="7.0.39",
            fixed_version=">= 8.4.31",
            affected_range="<8.4.31",
            aliases=[],
            references=[],
        )
        vhost = VhostConfig(file_path="/etc/nginx/sites-enabled/app.conf", server_names=["app.domain.tld"])
        stack_match = StackMatch(stack_name="nodejs", confidence="high", reasons=["package-lock.json"], root_path="/srv/app")
        stack_result = StackScanResult(
            stack=stack_match,
            dependencies=[dependency],
            issues=[AuditIssue(dependency, vulnerability, "npm-audit")],
            failures=[],
        )

        with patch("vhost_cve_monitor.scanner.load_vhosts", return_value=[vhost]), patch(
            "vhost_cve_monitor.scanner.detect_stacks", return_value=[stack_match]
        ), patch("vhost_cve_monitor.scanner.scan_stack", return_value=stack_result), patch.object(
            scanner.mailer, "send"
        ):
            scanner.scan_once()

        exported = scanner.export_findings()

        self.assertEqual(exported["findings_count"], 1)
        self.assertEqual(exported["breakdown"], {"MEDIUM": 1})
        self.assertEqual(exported["findings"][0]["vhost"], "app.domain.tld")
        self.assertEqual(exported["findings"][0]["dependency"], "postcss")
        self.assertEqual(exported["findings"][0]["advisory_summary"], "Line return parsing error in PostCSS")
        self.assertEqual(exported["findings"][0]["fixed_version"], ">= 8.4.31")


if __name__ == "__main__":
    unittest.main()
