import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.advisory_logic import (
    build_recommendation,
    canonical_advisory_id,
    merge_fixed_versions,
    strongest_severity,
)


class AdvisoryLogicTestCase(unittest.TestCase):
    def test_strongest_severity_never_lets_unknown_win(self) -> None:
        self.assertEqual(strongest_severity("MEDIUM", "UNKNOWN"), "MEDIUM")
        self.assertEqual(strongest_severity("UNKNOWN", "HIGH"), "HIGH")

    def test_canonical_advisory_id_prefers_standard_alias(self) -> None:
        self.assertEqual(
            canonical_advisory_id("OSV-2024-1234", ["CVE-2024-1000", "GHSA-abcd-1234-efgh"]),
            "CVE-2024-1000",
        )

    def test_merge_fixed_versions_deduplicates(self) -> None:
        self.assertEqual(merge_fixed_versions(">= 4.17.24", ">= 4.17.24"), ">= 4.17.24")

    def test_build_recommendation_is_stack_aware_for_npm(self) -> None:
        recommendation = build_recommendation("npm", "nodejs", "lodash", "4.17.23", ">= 4.17.24")

        self.assertIn("package-lock.json", recommendation)
        self.assertIn("npm audit fix", recommendation)
        self.assertIn("npm install lodash@", recommendation)
        self.assertIn("used at runtime or only during build/test", recommendation)

    def test_build_recommendation_handles_missing_fix_version(self) -> None:
        recommendation = build_recommendation("PyPI", "python", "requests", "2.32.5", None)

        self.assertIn("No fixed version is known", recommendation)
        self.assertIn("used at runtime or only during build/test", recommendation)


if __name__ == "__main__":
    unittest.main()
