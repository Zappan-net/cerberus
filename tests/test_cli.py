import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.cli import build_parser, main


class CliTestCase(unittest.TestCase):
    def test_test_mail_accepts_severity_and_category(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["test-mail", "--severity", "high", "--category", "digest"])

        self.assertEqual(args.command, "test-mail")
        self.assertEqual(args.severity, "HIGH")
        self.assertEqual(args.category, "digest")

    def test_test_mail_accepts_internal_error_category(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["test-mail", "--category", "internal-error"])

        self.assertEqual(args.category, "internal-error")

    def test_test_mail_accepts_stack_specific_overrides(self) -> None:
        parser = build_parser()

        args = parser.parse_args(
            [
                "test-mail",
                "--category",
                "vulnerability",
                "--stack",
                "nodejs",
                "--package",
                "lodash",
                "--installed-version",
                "4.17.23",
                "--fixed-version",
                ">= 4.17.24",
                "--advisory-id",
                "GHSA-35jh-r3h4-6jhm",
            ]
        )

        self.assertEqual(args.stack, "nodejs")
        self.assertEqual(args.package_name, "lodash")
        self.assertEqual(args.installed_version, "4.17.23")
        self.assertEqual(args.fixed_version, ">= 4.17.24")
        self.assertEqual(args.advisory_id, "GHSA-35jh-r3h4-6jhm")

    def test_export_findings_accepts_json_format_and_output_path(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["export-findings", "--format", "json", "--output", "/tmp/findings.json"])

        self.assertEqual(args.command, "export-findings")
        self.assertEqual(args.format, "json")
        self.assertEqual(args.output, "/tmp/findings.json")

    def test_scan_once_accepts_only_vhost_filters(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["scan-once", "--only-vhost", "app.example.net", "--only-vhost", "admin.*"])

        self.assertEqual(args.command, "scan-once")
        self.assertEqual(args.only_vhost, ["app.example.net", "admin.*"])

    def test_admin_subcommands_are_available(self) -> None:
        parser = build_parser()

        validate_args = parser.parse_args(["validate-config"])
        doctor_args = parser.parse_args(["doctor"])
        list_args = parser.parse_args(["list-vhosts"])
        explain_args = parser.parse_args(["explain-vhost", "app.example.net"])

        self.assertEqual(validate_args.command, "validate-config")
        self.assertEqual(doctor_args.command, "doctor")
        self.assertEqual(list_args.command, "list-vhosts")
        self.assertEqual(explain_args.command, "explain-vhost")
        self.assertEqual(explain_args.name, "app.example.net")

    def test_export_findings_output_writes_json_file(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            config_path = tmp_path / "config.yml"
            output_path = tmp_path / "exports" / "findings.json"
            config_path.write_text(
                """
nginx:
  sites_enabled_dir: /tmp/empty
scanner:
  command_timeout_seconds: 1
  network_timeout_seconds: 1
  repeated_failure_threshold: 3
  scan_interval_minutes: 60
  max_include_depth: 4
  max_directory_walk_depth: 1
notifications:
  email_to: [root@localhost]
  email_from: cerberus@localhost
  method: sendmail
  sendmail_path: /usr/sbin/sendmail
  max_emails_per_run: 20
  summary_only: true
state:
  database_path: %s/state.db
  state_dir: %s
  cve_cache_ttl_hours: 24
logging:
  level: INFO
  file: ""
filters: {}
                """ % (tmp_path, tmp_path),
                encoding="utf-8",
            )
            payload = {"scanned_at": "2026-04-13T10:00:00+00:00", "findings_count": 0, "breakdown": {}, "findings": []}
            stdout = io.StringIO()
            with patch("vhost_cve_monitor.cli.CerberusScanner.export_findings", return_value=payload):
                with redirect_stdout(stdout):
                    exit_code = main(["--config", str(config_path), "export-findings", "--output", str(output_path)])

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_path.exists())
            self.assertEqual(json.loads(output_path.read_text(encoding="utf-8")), payload)
            self.assertEqual(json.loads(stdout.getvalue()), payload)


if __name__ == "__main__":
    unittest.main()
