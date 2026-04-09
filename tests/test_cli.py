import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.cli import build_parser


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


if __name__ == "__main__":
    unittest.main()
