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


if __name__ == "__main__":
    unittest.main()
