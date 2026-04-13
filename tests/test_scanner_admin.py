import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.config import validate_config
from vhost_cve_monitor.scanner import CerberusScanner
from vhost_cve_monitor.models import StackScanResult


class ScannerAdminTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.sites_enabled = self.tmp_path / "sites-enabled"
        self.sites_enabled.mkdir()
        self.app_root = self.tmp_path / "app"
        self.app_root.mkdir()
        (self.app_root / "package-lock.json").write_text("{}", encoding="utf-8")
        self.blocked_root = self.tmp_path / "blocked"
        self.blocked_root.mkdir()
        (self.blocked_root / "package-lock.json").write_text("{}", encoding="utf-8")
        (self.sites_enabled / "app.conf").write_text(
            """
            server {
                server_name app.example.net;
                root %s;
            }
            """ % self.app_root,
            encoding="utf-8",
        )
        (self.sites_enabled / "blocked.conf").write_text(
            """
            server {
                server_name blocked.example.net;
                root %s;
            }
            """ % self.blocked_root,
            encoding="utf-8",
        )
        self.config = {
            "scanner": {
                "command_timeout_seconds": 1,
                "repeated_failure_threshold": 3,
                "network_timeout_seconds": 1,
                "scan_interval_minutes": 60,
                "max_include_depth": 4,
                "max_directory_walk_depth": 1,
                "default_roots": [],
            },
            "notifications": {
                "email_to": ["ops@example.net"],
                "email_from": "cerberus@example.net",
                "method": "sendmail",
                "sendmail_path": str(self.tmp_path / "missing-sendmail"),
                "max_emails_per_run": 20,
                "summary_only": True,
            },
            "state": {
                "database_path": str(self.tmp_path / "state" / "state.db"),
                "state_dir": str(self.tmp_path / "state"),
                "cve_cache_ttl_hours": 24,
            },
            "nginx": {"sites_enabled_dir": str(self.sites_enabled)},
            "filters": {"vhost_blocklist": ["blocked.example.net"]},
            "logging": {"level": "INFO", "file": str(self.tmp_path / "logs" / "cerberus.log")},
        }

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_validate_config_reports_conflicting_smtp_options(self) -> None:
        config = {
            "nginx": {"sites_enabled_dir": "/etc/nginx/sites-enabled", "include_globs": []},
            "scanner": {
                "scan_interval_minutes": 60,
                "command_timeout_seconds": 30,
                "network_timeout_seconds": 30,
                "max_include_depth": 4,
                "max_directory_walk_depth": 3,
                "repeated_failure_threshold": 3,
                "default_roots": [],
            },
            "notifications": {
                "email_to": ["ops@example.net"],
                "email_from": "cerberus@example.net",
                "method": "smtp",
                "smtp_host": "smtp.example.net",
                "smtp_port": 587,
                "smtp_ssl": True,
                "smtp_starttls": True,
                "smtp_username": "",
                "smtp_password": "",
                "smtp_password_env": "",
                "max_emails_per_run": 20,
                "summary_only": True,
            },
            "state": {"database_path": "/tmp/state.db", "state_dir": "/tmp", "cve_cache_ttl_hours": 24},
            "logging": {"level": "INFO", "file": ""},
            "filters": {},
        }

        validation = validate_config(config)

        self.assertTrue(validation["errors"])
        self.assertIn("notifications.smtp_ssl and notifications.smtp_starttls cannot both be enabled", validation["errors"])

    def test_list_vhosts_returns_filter_and_stack_context(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)

        listing = scanner.list_vhosts()

        self.assertEqual(listing["count"], 2)
        app_vhost = next(item for item in listing["vhosts"] if item["primary_server_name"] == "app.example.net")
        blocked_vhost = next(item for item in listing["vhosts"] if item["primary_server_name"] == "blocked.example.net")
        self.assertTrue(app_vhost["passes_filters"])
        self.assertEqual(app_vhost["candidate_roots"], [str(self.app_root)])
        self.assertEqual(app_vhost["detected_stacks"][0]["stack_name"], "nodejs")
        self.assertFalse(blocked_vhost["passes_filters"])
        self.assertIn("vhost matched filters.vhost_blocklist", blocked_vhost["filter_reasons"])

    def test_explain_vhost_returns_detection_details(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)

        explanation = scanner.explain_vhost("app.example.net")

        self.assertEqual(explanation["matches_count"], 1)
        match = explanation["matches"][0]
        self.assertEqual(match["primary_server_name"], "app.example.net")
        self.assertEqual(match["candidate_roots"], [str(self.app_root)])
        self.assertEqual(match["detected_stacks"][0]["stack_name"], "nodejs")

    def test_doctor_reports_missing_sendmail_binary(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)

        report = scanner.doctor()

        self.assertEqual(report["status"], "error")
        self.assertTrue(any(check["name"] == "notifications.sendmail" and check["status"] == "error" for check in report["checks"]))
        self.assertTrue(any("sendmail binary missing" in message for message in report["errors"]))

    def test_collect_scan_data_can_be_restricted_to_one_vhost(self) -> None:
        scanner = CerberusScanner(config=self.config, dry_run=True, allow_network=False)

        def fake_scan_stack(stack, cve_db, timeout, allow_network):
            return StackScanResult(stack=stack)

        with patch("vhost_cve_monitor.scanner.scan_stack", side_effect=fake_scan_stack):
            _now, results, issue_occurrences, failure_notifications = scanner._collect_scan_data(only_vhosts=["app.example.net"])

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].vhost.primary_server_name, "app.example.net")
        self.assertEqual(issue_occurrences, [])
        self.assertEqual(failure_notifications, [])


if __name__ == "__main__":
    unittest.main()
